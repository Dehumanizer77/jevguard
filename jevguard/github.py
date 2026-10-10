"""Which GitHub repository a `gh` command is about.

Used to treat what `gh` returns about the owner's own repositories less strictly than what it
returns about anyone else's. Everything here errs towards "cannot tell": a command whose
repository is not plain to see is handled as any other outside content.
"""

from __future__ import annotations

import fnmatch
import os
import re

_NAME = r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+"
_GITHUB_URL = re.compile(r"(?:https?://(?:[^@/\s]+@)?github\.com/|git@github\.com:|ssh://git@github\.com/)"
                         r"(" + _NAME + r"?)(?:\.git)?/?", re.I)
_API_PATH = re.compile(r"/?repos/(" + _NAME + r")(?:/.*)?")
# Subcommands that act on one repository: the one named with --repo, else the one checked out
# in the directory. `search`, `status`, `gist` and `api` paths outside repos/ range over GitHub.
_REPO_SCOPED = {"pr", "issue", "run", "workflow", "release", "label", "cache", "secret", "variable", "ruleset"}


def slug(value: str) -> str | None:
    """owner/name from what `--repo` or a git remote holds; None for another host or anything else."""
    value = value.strip()
    m = _GITHUB_URL.fullmatch(value)
    if m:
        return m.group(1)
    value = re.sub(r"^github\.com/", "", value, flags=re.I)
    return value if re.fullmatch(_NAME, value) else None


# ---- the checkout a command runs in ----------------------------------------------------------------
# Git's settings files are searched as text, not parsed: a key counts wherever it stands (at the
# start of a line or after a section header on the same line, in a comment too), and anything
# that is not exactly the plain form ends in "cannot tell". Wider than the truth, never narrower.
_KEY = r"(?:^|[\]\s])"
_REMOTE_HEADER = re.compile(r"\[\s*remote\b[^\]\n]*\]?", re.I)
_ORIGIN_HEADER = re.compile(r'\[\s*(?i:remote)\s+"origin"\s*\]')
_URL_KEY = re.compile(_KEY + r"url\s*=[ \t]*(\S*)", re.I | re.M)
_BRANCH_REMOTE = re.compile(_KEY + r"remote\s*=[ \t]*(\S*)", re.I | re.M)
_GH_RESOLVED = re.compile(_KEY + r"gh-resolved\s*=[ \t]*(\S*)", re.I | re.M)
# Settings that send git somewhere other than the address written for origin, or that pull in
# settings this reader does not see.
_ELSEWHERE = re.compile(_KEY + r"(?:pushurl|pushdefault|pushremote|(?:push)?insteadof|worktreeconfig)\s*=|"
                        r"^\s*\[\s*include", re.I | re.M)
_GIT_ENV = ("GIT_DIR", "GIT_WORK_TREE", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_COUNT",
            "GIT_CONFIG_PARAMETERS", "GIT_SSH", "GIT_SSH_COMMAND", "GIT_PROXY_COMMAND")


def _read(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(200_000)
    except OSError:
        return None


def _checkout_settings(directory: str) -> str | None:
    """The text of .git/config of the checkout around a directory."""
    d = directory
    for _ in range(40):
        config = os.path.join(d, ".git", "config")
        if os.path.isfile(config):
            return _read(config)
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent
    return None


def _user_git_settings() -> str:
    home = os.path.expanduser("~")
    folder = os.environ.get("XDG_CONFIG_HOME") or os.path.join(home, ".config")
    return "\n".join(_read(p) or "" for p in (os.path.join(home, ".gitconfig"), os.path.join(folder, "git", "config")))


def origin_repo(directory: str) -> str | None:
    """The one github.com repository the git checkout around a directory talks to, or None when
    that is not plain. It is plain when origin is the only remote and has one address, every
    branch follows origin, and neither the checkout's settings nor the user's own hold anything
    that sends git elsewhere (pushurl, insteadOf, pushDefault, an include). With a second remote
    `gh` may pick that one, and a bare `git push` may go to it."""
    text = _checkout_settings(directory)
    if text is None or any(name in os.environ for name in _GIT_ENV):
        return None
    if _ELSEWHERE.search(text) or _ELSEWHERE.search(_user_git_settings()):
        return None
    remotes, urls = _REMOTE_HEADER.findall(text), _URL_KEY.findall(text)
    if len(remotes) != 1 or not _ORIGIN_HEADER.fullmatch(remotes[0]) or len(urls) != 1:
        return None
    if any(remote not in ("origin", ".") for remote in _BRANCH_REMOTE.findall(text)):
        return None
    if any(chosen != "base" for chosen in _GH_RESOLVED.findall(text)):
        return None  # `gh repo set-default` pointed gh at another repository of the same network
    return slug(urls[0])


# ---- git push beside gh -----------------------------------------------------------------------------
_PUSH_FLAGS = {"-u", "--set-upstream", "-q", "--quiet", "-v", "--verbose", "-f", "--force", "--force-with-lease",
               "--tags", "--follow-tags", "--no-verify", "-n", "--dry-run", "-d", "--delete"}
_REFSPEC = re.compile(r"\+?[A-Za-z0-9._/-]*(?::[A-Za-z0-9._/-]*)?")


def push_repos(args: list[str], dirs: list[str]) -> list[str] | None:
    """The github.com repositories a `git push` with these arguments sends to, one for each
    directory the command may be running in; None when that cannot be told. It can be told when
    the push names origin or no remote at all, uses everyday options, and the checkout talks to
    one repository only (see origin_repo). A remote given as an address, another remote's name,
    --receive-pack, --recurse-submodules: not told."""
    words = [a for a in args if a not in _PUSH_FLAGS]
    if any(a.startswith("-") for a in words):
        return None
    if words and (words[0] != "origin" or not all(_REFSPEC.fullmatch(w) for w in words[1:])):
        return None
    repos = [origin_repo(d) for d in dirs] or [None]
    return None if any(r is None for r in repos) else repos


# ---- gh api, taken apart ---------------------------------------------------------------------------
_API_FLAGS = {"-i", "--include", "--paginate", "--silent", "--slurp", "--verbose"}
_API_VALUES = {"-X": "method", "--method": "method", "-f": "field", "--raw-field": "field", "-F": "field",
               "--field": "field", "--input": "field", "--hostname": "host", "-H": "", "--header": "",
               "-q": "", "--jq": "", "-t": "", "--template": "", "-p": "", "--preview": "", "--cache": ""}


def _api(args: list[str]) -> tuple[str, str, bool] | None:
    """(endpoint, method, takes what it sends from a file) of the arguments after `gh api`. None
    when they hold an option this reader does not know, another host, two different methods, or
    anything but one endpoint: the caller then assumes nothing about the call."""
    methods, fields, from_file, words, i = set(), False, False, [], 0
    while i < len(args):
        a = args[i]
        i += 1
        if not a.startswith("-"):
            words.append(a)
            continue
        if a.startswith("--"):
            name, attached, value = a.partition("=")
        else:
            name, value = a[:2], a[2:]  # -XGET, -fkey=value
            attached = value
        if name in _API_FLAGS and not attached:
            continue
        kind = _API_VALUES.get(name)
        if kind is None or kind == "host":
            return None
        if not attached:
            if i >= len(args):
                return None
            value = args[i]
            i += 1
        if kind == "method":
            methods.add(value.upper())
        fields = fields or kind == "field"
        # --input names a file (or - for what is piped in); -F key=@file reads the value from one.
        # -f takes its value as written.
        from_file = from_file or name == "--input" or (
            name in ("-F", "--field") and value.partition("=")[2].startswith("@"))
    if len(words) != 1 or len(methods) > 1:
        return None
    # gh's own rule: GET, or POST once a field is given, unless a method is named
    return words[0], (methods.pop() if methods else "POST" if fields else "GET"), from_file


def _api_repo(endpoint: str) -> str | None:
    """owner/name of a repos/... endpoint that leads nowhere else: no `..`, no escape, no
    doubled slash in the path."""
    path = endpoint.split("?", 1)[0]
    if "%" in path or "#" in path or "\\" in path or any(s in ("", ".", "..") for s in path.lstrip("/").split("/")):
        return None
    m = _API_PATH.fullmatch(path)
    return m.group(1) if m else None


# What `gh <noun> <verb>` changes something with. gate.py asks about these.
WRITE_VERBS = {"create", "comment", "edit", "merge", "close", "reopen", "delete", "upload", "set", "run", "fork",
               "review", "ready", "lock", "unlock", "transfer", "rename", "archive", "unarchive", "sync", "enable",
               "disable", "rerun", "cancel", "add", "remove", "import", "pin", "unpin", "develop", "revert"}
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
# Replies that hold nothing but what the command itself sent: the address of the new pull
# request, the comment just posted. A change to something that already exists is not one: it
# returns or names the whole thing, and in a public repository that text may be a stranger's
# (`gh api -X PATCH .../issues/7 -f state=closed` returns the issue, `gh issue close` its title).
_ECHO_VERBS = {"create", "comment", "edit"}
_ECHO_API = re.compile(r"/?repos/[^/]+/[^/]+/(?:issues|pulls|releases|labels|(?:issues|pulls)/\d+/comments|"
                       r"pulls/\d+/reviews)/?")


def gh_writes(argv: list[str]) -> bool:
    """The invocation plainly changes something on GitHub. Read strictly, the other way round
    from the gate: there a doubtful call is asked about, here a doubtful call is not a write.
    `gh api -X GET ... -f per_page=10` is a read whatever fields it carries."""
    args = argv[1:]
    if args[:1] == ["api"]:
        call = _api(args[1:])
        return bool(call) and call[1] not in _SAFE_METHODS
    words = [a for a in args if not a.startswith("-")]
    return len(words) > 1 and args[0] in _REPO_SCOPED and words[1] in WRITE_VERBS


def gh_sends_file(argv: list[str]) -> bool:
    """A `gh api` call that takes what it sends from a file or from what it is piped."""
    call = _api(argv[2:]) if argv[1:2] == ["api"] else None
    return bool(call) and call[2]


def gh_echo(argv: list[str]) -> bool:
    """The reply to this invocation is what it just created and nothing else: what the command
    itself says. A new issue whose body came from a file comes back with that file in it, and
    that is no more the command's own text than `cat file` would be."""
    if not gh_writes(argv):
        return False
    args = argv[1:]
    if args[0] == "api":
        endpoint, method, from_file = _api(args[1:])
        return method == "POST" and not from_file and bool(_ECHO_API.fullmatch(endpoint.split("?", 1)[0]))
    return [a for a in args if not a.startswith("-")][1] in _ECHO_VERBS


_SOCKET = re.compile(r"(?m)^\s*http_unix_socket\s*:[ \t]*(?!(?:\"\"|'')?[ \t]*(?:#.*)?$)\S")


def rerouted() -> bool:
    """gh is set to send its requests through a socket. What answers there is not known to be
    GitHub, so nothing gh returns is then treated as coming from the owner's own repositories."""
    env = os.environ
    folder = env.get("GH_CONFIG_DIR") or os.path.join(
        env.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config"), "gh")
    for name in ("config.yml", "hosts.yml"):
        try:
            with open(os.path.join(folder, name), encoding="utf-8", errors="replace") as f:
                if _SOCKET.search(f.read(200_000)):
                    return True
        except OSError:
            pass
    return False


def gh_repos(argv: list[str], dirs: list[str]) -> list[str] | None:
    """The repositories one `gh` invocation is about, or None when that cannot be told."""
    args = argv[1:]
    if any(a.split("=", 1)[0] == "--hostname" for a in args):
        return None  # another server: the same owner/name there is someone else's
    if args[:1] == ["api"]:
        call = _api(args[1:])
        repo = _api_repo(call[0]) if call else None
        return [repo] if repo else None
    words, named, skip = [], [], False
    for i, a in enumerate(args):
        if skip:
            skip = False
        elif re.fullmatch(r"-[A-Za-z]+R.*", a) and not a.startswith("-R"):
            return None  # -cR owner/name: the repository is named, in a run of short options
        elif a in ("-R", "--repo"):
            named.append(args[i + 1] if i + 1 < len(args) else "")
            skip = True
        elif a.startswith("--repo="):
            named.append(a.split("=", 1)[1])
        elif a.startswith("-R") and len(a) > 2:
            named.append(a[2:])
        elif not a.startswith("-"):
            words.append(a)
    if not words:
        return None
    if words[0] == "repo" and words[1:2] == ["view"]:
        named = named or words[2:3]
    elif words[0] not in _REPO_SCOPED:
        return None
    if named:
        repos = [slug(n) for n in named]
    else:
        repos = [origin_repo(d) for d in dirs] or [None]
    return None if any(r is None for r in repos) else repos


def is_own(repo: str, patterns: list) -> bool:
    return any(fnmatch.fnmatchcase(repo.lower(), str(p).lower()) for p in patterns)
