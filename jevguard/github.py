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


def origin_repo(directory: str) -> str | None:
    """The github.com repository that the git checkout around a directory calls origin."""
    d = directory
    for _ in range(40):
        config = os.path.join(d, ".git", "config")
        if os.path.isfile(config):
            break
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent
    else:
        return None
    try:
        with open(config, encoding="utf-8", errors="replace") as f:
            text = f.read(200_000)
    except OSError:
        return None
    m = re.search(r'^\[remote "origin"\][^\[]*?^\s*url\s*=\s*(\S+)', text, re.M | re.S)
    return slug(m.group(1)) if m else None


# ---- gh api, taken apart ---------------------------------------------------------------------------
_API_FLAGS = {"-i", "--include", "--paginate", "--silent", "--slurp", "--verbose"}
_API_VALUES = {"-X": "method", "--method": "method", "-f": "field", "--raw-field": "field", "-F": "field",
               "--field": "field", "--input": "field", "--hostname": "host", "-H": "", "--header": "",
               "-q": "", "--jq": "", "-t": "", "--template": "", "-p": "", "--preview": "", "--cache": ""}


def _api(args: list[str]) -> tuple[str, str, bool] | None:
    """(endpoint, method, sends fields) of the arguments after `gh api`. None when they hold an
    option this reader does not know, another host, two different methods, or anything but one
    endpoint: the caller then assumes nothing about the call."""
    methods, fields, words, i = set(), False, [], 0
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
    if len(words) != 1 or len(methods) > 1:
        return None
    # gh's own rule: GET, or POST once a field is given, unless a method is named
    return words[0], (methods.pop() if methods else "POST" if fields else "GET"), fields


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


def gh_echo(argv: list[str]) -> bool:
    """The reply to this invocation is what it just created and nothing else."""
    if not gh_writes(argv):
        return False
    args = argv[1:]
    if args[0] == "api":
        endpoint, method, _ = _api(args[1:])
        return method == "POST" and bool(_ECHO_API.fullmatch(endpoint.split("?", 1)[0]))
    return [a for a in args if not a.startswith("-")][1] in _ECHO_VERBS


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
