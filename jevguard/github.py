"""Which GitHub repository a `gh` command is about.

Used to withhold what `gh` returns about the owner's own repositories from a higher score up
than what it returns about anyone else's. The repository has to be written in the command
(`--repo owner/name`, `api repos/owner/name/...`); it is never taken from the directory the
command runs in, because which repository gh then picks depends on the remotes and settings of
that checkout. Everything here errs towards "cannot tell".
"""

from __future__ import annotations

import fnmatch
import os
import re

_NAME = r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+"
_API_PATH = re.compile(r"/?repos/(" + _NAME + r")(?:/.*)?")
# Subcommands that act on the one repository their --repo option names. `search`, `status`,
# `gist` and `api` paths outside repos/ range over GitHub; `secret`, `variable` and `ruleset`
# can be pointed at an organisation instead (--org), so they are not read either.
_REPO_SCOPED = {"pr", "issue", "run", "workflow", "release", "label"}
# What `gh <noun> <verb>` changes something with. gate.py asks about these.
WRITE_VERBS = {"create", "comment", "edit", "merge", "close", "reopen", "delete", "upload", "set", "run", "fork",
               "review", "ready", "lock", "unlock", "transfer", "rename", "archive", "unarchive", "sync", "enable",
               "disable", "rerun", "cancel", "add", "remove", "import", "pin", "unpin", "develop", "revert"}


def slug(value: str) -> str | None:
    """owner/name from what `--repo` holds; None for another host or anything else."""
    value = re.sub(r"^github\.com/", "", value.strip(), flags=re.I)
    return value if re.fullmatch(_NAME, value) else None


# ---- gh api, taken apart ---------------------------------------------------------------------------
_API_FLAGS = {"-i", "--include", "--paginate", "--silent", "--slurp", "--verbose"}
_API_VALUES = {"-X", "--method", "-f", "--raw-field", "-F", "--field", "--input", "-H", "--header", "-q", "--jq",
               "-t", "--template", "-p", "--preview", "--cache"}  # not --hostname: that is another server


def _endpoint(args: list[str]) -> str | None:
    """The endpoint among the arguments after `gh api`. None when they hold an option this
    reader does not know, another host, or anything but one endpoint: the caller then assumes
    nothing about the call."""
    words, i = [], 0
    while i < len(args):
        a = args[i]
        i += 1
        if not a.startswith("-"):
            words.append(a)
            continue
        if a.startswith("--"):
            name, attached, _ = a.partition("=")
        else:
            name, attached = a[:2], a[2:]  # -XGET, -fkey=value
        if name in _API_FLAGS and not attached:
            continue
        if name not in _API_VALUES:
            return None
        if not attached:
            if i >= len(args):
                return None
            i += 1  # its value is the next word
    return words[0] if len(words) == 1 else None


def _api_repo(endpoint: str) -> str | None:
    """owner/name of a repos/... endpoint that leads nowhere else: no `..`, no escape, no
    doubled slash in the path."""
    path = endpoint.split("?", 1)[0]
    if "%" in path or "#" in path or "\\" in path or any(s in ("", ".", "..") for s in path.lstrip("/").split("/")):
        return None
    m = _API_PATH.fullmatch(path)
    return m.group(1) if m else None


# The repository option as gh takes it, and anything that could be one: -R also at the end of a
# run of short options (-cR).
_REPO_OPTION = re.compile(r"-R.*|--repo(?:=.*)?")
_COULD_BE_ONE = re.compile(r"-[A-Za-z]*R.*|--repo(?:=.*)?")


def gh_repos(argv: list[str]) -> list[str] | None:
    """The repository one `gh` invocation is addressed to, as a list of one, or None when it
    names none or it is not certain which.

    For `gh api` the options are few and known, and the endpoint is found by going through
    them. The other subcommands have hundreds of options between them, and which of those take
    a value is not known here; without that, `--label --repo=acme/widget` cannot be told from a
    repository option by looking at it. So the option counts only where gh itself is certain to
    read an option, whatever the others are: straight after a word that is not an option (the
    subcommand, a value, an argument) or after `--option=value`. After a bare option it may be
    that option's value; after `--` everything is an argument. And there has to be exactly one
    thing in the command that could be it."""
    args = argv[1:]
    if "--" in args or any(a.split("=", 1)[0] == "--hostname" for a in args):
        return None  # --hostname is another server: the same owner/name there is someone else's
    if args[:1] == ["api"]:
        endpoint = _endpoint(args[1:])
        repo = _api_repo(endpoint) if endpoint else None
        return [repo] if repo else None
    found = [i for i, a in enumerate(args) if _COULD_BE_ONE.fullmatch(a)]
    if args[:2] == ["repo", "view"]:  # takes the repository as its first argument, and no option for it
        repo = slug(args[2]) if len(args) > 2 and not found else None
        return [repo] if repo else None
    if not args or args[0] not in _REPO_SCOPED or len(found) != 1:
        return None
    i = found[0]
    option, before = args[i], args[i - 1] if i else "-"
    if not _REPO_OPTION.fullmatch(option) or (before.startswith("-") and not (before.startswith("--") and "=" in before)):
        return None
    if option in ("-R", "--repo"):
        value = args[i + 1] if i + 1 < len(args) else ""
    else:
        value = option[7:] if option.startswith("--repo=") else option[2:]
    repo = slug(value)
    return [repo] if repo else None


def is_own(repo: str, patterns: list) -> bool:
    return any(fnmatch.fnmatchcase(repo.lower(), str(p).lower()) for p in patterns)


# ---- gh sent somewhere else ------------------------------------------------------------------------
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
