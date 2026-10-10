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


def gh_repos(argv: list[str], dirs: list[str]) -> list[str] | None:
    """The repositories one `gh` invocation is about, or None when that cannot be told."""
    args = argv[1:]
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
    if words[0] == "api":
        if named:
            return None  # gh api takes no --repo; a command that pairs them is not what it seems
        repos = [m.group(1) for w in words[1:] for m in [_API_PATH.fullmatch(w)] if m]
        return repos or None
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
