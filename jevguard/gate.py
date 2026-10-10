"""Actions that could carry out an injected instruction: sending data out, publishing, writing
to files that run later, and changing the guard itself. No model here, only reading of the call;
the detector can miss an injection, and this is the layer that still stands when it does.

It reads what a command says in plain sight (see shell.py). A command that hides what it does,
by encoding it or by running a script written earlier, gets past it: the agent and the owner
are the same operating-system user, so this is an approval step, not a wall.
"""

from __future__ import annotations

import fnmatch
import os
import re

from . import shell
from .github import WRITE_VERBS
from .shell import canonical, under

CODE_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
# curl short options that take a value: in a bundle like -ofile the rest is that value, not more options.
_CURL_VALUE_OPTS = set("AbcCDeEhHKmoPQrtuUwxyYz")
_CURL_DATA_LONG = {"data", "data-raw", "data-binary", "data-urlencode", "data-ascii", "form", "form-string",
                   "upload-file", "json", "config", "mail-rcpt", "url-query"}
_WGET_DATA = {"--post-data", "--post-file", "--body-data", "--body-file"}
_HTTPIE_ITEM = re.compile(r"[\w.\-\[\]]+(?::=|=(?!=)|@)")
_CONNECT = {"ssh", "scp", "sftp", "ftp", "nc", "ncat", "netcat", "socat", "telnet"}
_MAIL = {"mail", "mailx", "sendmail", "msmtp", "mutt", "swaks"}
_MCP_WRITE = re.compile(r"(?:^|_)(?:send|create|update|delete|post|write|reply|upload|share|publish|batch|"
                        r"move|remove|add|insert|modify|forward|draft|edit|set|invite|comment)(?:_|$)", re.I)
# Files that run or grant access later, and the settings curl, wget and gh read on their own: a
# proxy or a socket written there decides whose content every later request returns.
_STARTUP = re.compile(r"(?:^|/)(?:\.ssh(?:/|$)|\.claude/(?:hooks(?:/|$)|CLAUDE\.md$)|\.git/hooks(?:/|$)|"
                      r"\.bashrc$|\.bash_profile$|\.bash_login$|\.profile$|\.zshrc$|\.zprofile$|\.gitconfig$|"
                      r"\.config/systemd(?:/|$)|\.config/autostart(?:/|$)|CLAUDE\.md$|\.mcp\.json$|"
                      r"\.curlrc$|\.config/curlrc$|\.wgetrc$|\.netrc$|\.config/gh(?:/|$))")
# The files an agent's hooks live in: Claude Code's settings and what the other adapters install
# into (agents/setup.py). One line in any of them switches the guard off for that agent.
_SETTINGS = re.compile(r"(?:^|/)(?:\.claude/settings[^/]*\.json|\.(?:grok|copilot)/hooks/[^/]+\.json|"
                       r"\.cursor/hooks\.json|\.codex/hooks\.json|\.hermes/plugins/jevguard(?:/.*)?)$")
_ADMIN = {"mode", "gate", "install", "uninstall", "release", "show", "trust", "untrust", "own", "disown"}
# The same commands named inside code the reader cannot take apart: os.system("jevguard uninstall"),
# ['.../jevguard', 'release', id], python3 -m jevguard.cli mode block. Only where the word stands
# as the program and the subcommand is its next argument. The first version matched any of those
# words within eighty characters, and so asked about `grep ... jevguard/gate.py` and about
# `gh pr create --repo owner/jevguard --head release-notes`: a path and a repository name.
_NEXT = r"['\"]?(?:\s*,\s*|\s+)['\"]?"
_ADMIN_TEXT = re.compile(
    r"(?<![\w.-])(?:[\w./~-]*/)?jevguard(?:\.cli)?" + _NEXT
    + r"(?:--settings(?:=\S+?|" + _NEXT + r"\S+?)" + _NEXT + r")?"
    + r"(?:" + "|".join(sorted(_ADMIN)) + r")\b(?![\w./-])")
_LONG_URL = 300  # a fetch can carry data out in its address
_UNREADABLE = "could not be read as a command, so what it does cannot be ruled out"


# Programs that only read what they are pointed at. They matter for one question: a command that
# names a directory above the guard's files (`ls ~`, `du -sh ~/.claude`) is not a change to them.
_READ_ONLY = {"ls", "cat", "head", "tail", "less", "more", "grep", "egrep", "fgrep", "rg", "ag", "du", "df", "stat",
              "file", "wc", "tree", "pwd", "cd", "pushd", "echo", "printf", "test", "[", "realpath", "readlink",
              "basename", "dirname", "sort", "diff", "cmp", "md5sum", "sha1sum", "sha256sum", "jq", "cut",
              "tr", "nl", "od", "strings", "which", "type", "true", "false", "date", "id", "whoami",
              "hostname", "uname", "ps"}  # not uniq or xxd: their second file argument is written
_FIND_ACTS = {"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls"}
_SETTINGS_NAMES = ("settings.json", "settings.local.json")


def _reads_only(argv: list[str]) -> bool:
    program = os.path.basename(argv[0])
    if program == "find":
        return not _FIND_ACTS & set(argv)
    if program == "sed":
        return not any(a == "--in-place" or a.startswith("--in-place=") or
                       (a.startswith("-") and not a.startswith("--") and "i" in a) for a in argv[1:])
    return program in _READ_ONLY


def _method(value: str) -> bool:
    return bool(value) and value.upper() not in _SAFE_METHODS


def _curl_sends(args: list[str]) -> bool:
    for i, a in enumerate(args):
        following = args[i + 1] if i + 1 < len(args) else ""
        if a.startswith("--"):
            name, _, value = a[2:].partition("=")
            if name in _CURL_DATA_LONG or (name == "request" and _method(value or following)):
                return True
        elif a.startswith("-") and len(a) > 1:  # a bundle of short options: -sSLd, -Ffile=@x, -Tfile, -XPOST
            for j, c in enumerate(a[1:], 1):
                if c in "dFTK":  # data, form, upload; -K reads its options, body included, from a file
                    return True
                if c == "X":
                    if _method(a[j + 1:] or following):
                        return True
                    break  # a safe method says nothing about a body: keep reading the other options
                if c in _CURL_VALUE_OPTS:
                    break
    return False


def _wget_sends(args: list[str]) -> bool:
    for i, a in enumerate(args):
        name, _, value = a.partition("=")
        if name in _WGET_DATA or (name == "--method" and _method(value or (args[i + 1] if i + 1 < len(args) else ""))):
            return True
    return False


def _git_subcommand(args: list[str]) -> str:
    skip = False
    for a in args:
        if skip:
            skip = False
        elif a in ("-C", "-c", "--git-dir", "--work-tree", "--namespace"):
            skip = True
        elif not a.startswith("-"):
            return a
    return ""


def _git_config_writes(args: list[str]) -> bool:
    rest = args[args.index("config") + 1:]
    if {"--add", "--replace-all", "--unset", "--unset-all", "--rename-section", "--remove-section", "--edit", "-e"} & set(rest):
        return True
    if any(a in ("--list", "-l") or a.startswith("--get") for a in rest):
        return False
    names, skip = 0, False
    for a in rest:
        if skip:
            skip = False
        elif a in ("-f", "--file", "--type", "--default", "--blob"):
            skip = True
        elif not a.startswith("-"):
            names += 1
    return names >= 2  # a name and a value


def _gh_changes(args: list[str]) -> bool:
    words = [a for a in args if not a.startswith("-")]
    if not words:
        return False
    if words[0] != "api":
        return len(words) > 1 and words[1] in WRITE_VERBS
    for i, a in enumerate(args):
        following = args[i + 1] if i + 1 < len(args) else ""
        name, _, value = a.partition("=")
        if name in ("--field", "--raw-field", "--input"):
            return True
        if name == "--method" and _method(value or following):
            return True
        if not a.startswith("--") and len(a) > 1 and a[0] == "-":
            if a[1] in "fF":  # -f key=value, -fkey=value: gh api switches to POST
                return True
            if a[1] == "X" and _method(a[2:] or following):
                return True
    return False


_HTTP_CLIENTS = {"curl", "wget", "xh", "http", "https", "httpie", "aria2c"}
_RISK_PROGRAMS = _HTTP_CLIENTS | _CONNECT | _MAIL | {"git", "gh", "rsync", "himalaya", "npm", "pnpm", "yarn", "cargo",
                                                     "twine", "docker", "crontab", "systemctl"}


def _program_risk(argv: list[str]) -> str:
    program, args = os.path.basename(argv[0]), argv[1:]
    if program == "curl" and _curl_sends(args):
        return "sends data with an HTTP request"
    if program == "wget" and _wget_sends(args):
        return "sends data with an HTTP request"
    if program in ("xh", "http", "https", "httpie") and any(
            _method(a) and a.isalpha() and a.isupper() or (_HTTPIE_ITEM.match(a) and "://" not in a) for a in args):
        return "sends data with an HTTP request"
    if program in _HTTP_CLIENTS:
        # No body is needed to carry data out: the address and the headers do it as well.
        if any("$" in a for a in args):
            return "sends an HTTP request whose address or headers are filled in when it runs"
        if any(len(a) > _LONG_URL for a in args if "://" in a):
            return "fetches a very long address, which can carry data out"
    if program == "git" and _git_subcommand(args) == "push":
        return "git push"
    if program == "git" and _git_subcommand(args) == "config" and _git_config_writes(args):
        return "changes git configuration, which can make git run commands later"
    if program == "gh" and _gh_changes(args):
        return "changes something on GitHub"
    if program in _CONNECT or (program == "rsync" and any(":" in a for a in args if not a.startswith("-"))):
        return "opens a connection to another machine"
    if program in _MAIL or (program == "himalaya" and {"send", "write", "reply", "forward"} & set(args)):
        return "sends mail"
    if (program in ("npm", "pnpm", "yarn", "cargo") and "publish" in args) or \
            (program == "twine" and "upload" in args) or (program == "docker" and "push" in args):
        return "publishes a package"
    if (program == "crontab" and args != ["-l"]) or \
            (program == "systemctl" and {"enable", "start", "restart"} & set(args)) or program in ("at", "batch"):
        return "schedules or starts a service"
    return ""


def risky(tool: str, tool_input: dict, cwd: str = "") -> str:
    """Why this call could act on an injected instruction, or an empty string."""
    if tool == "Bash":
        try:
            c = shell.read(str(tool_input.get("command") or ""), cwd)
        except Exception:
            return _UNREADABLE
        for argv in c.programs:
            why = _program_risk(argv)
            if not why and not _reads_only(argv):
                # proxychains curl ..., strace -f git push ...: the program that counts is further in
                why = next((w for i in range(1, len(argv)) if os.path.basename(argv[i]) in _RISK_PROGRAMS
                            for w in [_program_risk(argv[i:])] if w), "")
            if why:
                return why
        if any(_STARTUP.search(p) for p in c.paths):
            return "touches a file that runs or grants access later"
        return ""
    if tool == "WebFetch":
        url = str(tool_input.get("url") or "")
        return "fetches a very long address, which can carry data out" if len(url) > _LONG_URL else ""
    if tool in ("Write", "Edit", "NotebookEdit"):
        path = canonical(str(tool_input.get("file_path") or ""), cwd)
        return "writes to a file that runs or grants access later" if _STARTUP.search(path) else ""
    if tool.startswith("mcp__"):
        name = tool.rsplit("__", 1)[-1]
        return "MCP tool that changes or sends something" if _MCP_WRITE.search(name) else ""
    return ""


def _settings_glob(pattern: str) -> bool:
    """The pattern can match a Claude Code settings file: <dir>/.claude/settings*.json."""
    segs = pattern.split("/")
    return (len(segs) >= 2 and fnmatch.fnmatchcase(".claude", segs[-2])
            and any(fnmatch.fnmatchcase(name, segs[-1]) for name in _SETTINGS_NAMES))


def guard_change(tool: str, tool_input: dict, cfg, cwd: str = "") -> str:
    """Why this call would change the guard itself (its settings, state, release list, code, or
    the Claude Code settings that run it), or an empty string. Asked about in every session."""
    roots = [canonical(str(cfg.config_dir)), canonical(str(cfg.state_dir)), CODE_ROOT]
    # The originals the owner released. The agent has to read them, so looking is free; putting
    # a file there, changing one or removing one is asked about like a change to a settings file.
    released = canonical(str(cfg.released_dir))
    # What must not be removed from above either: the guard's directories and the user's settings.
    targets = roots + [released] + [canonical(os.path.join("~", ".claude", name)) for name in _SETTINGS_NAMES]

    def protected(path: str) -> bool:
        return bool(_SETTINGS.search(path)) or any(under(path, r) for r in [*roots, released])

    def above(path: str) -> bool:
        return any(path != t and under(t, path) for t in targets)

    def kind(path: str) -> str:
        if any(under(path, r) or shell.glob_reaches(path, r) for r in roots):
            return "one of the guard's own files"
        if under(path, released) or shell.glob_reaches(path, released):
            return "the directory of originals the owner released (the agent reads those unscanned)"
        return "a Claude Code settings file (the hooks that run the guard are set there)"

    # Every reason names the program and the exact path that set it off. The person asked to
    # approve cannot review a two-hundred-line command; they can check one named thing.
    if tool in ("Write", "Edit", "NotebookEdit"):
        path = canonical(str(tool_input.get("file_path") or ""), cwd)
        return f"{tool} writes to {_show(path)}, {kind(path)}" if protected(path) else ""
    if tool in ("Read", "Grep"):
        # An agent's own file tools, and the API key and the seal key. Claude Code is kept away
        # from them by the two permission rules `install` writes (its hook is not started before
        # a Read); for every other agent this is what stands in front of them. A search from a
        # directory above reads them as well.
        path = canonical(str(tool_input.get("file_path") or tool_input.get("path") or ""), cwd)
        keys = roots[:2]
        if any(under(path, r) for r in keys):
            return f"{tool} reads {_show(path)}, one of the guard's own files (the API key is kept there)"
        if tool == "Grep" and any(under(r, path) for r in keys):
            return f"{tool} searches {_show(path)}, which holds the guard's own files (the API key is kept there)"
        return ""
    if tool != "Bash":
        return ""
    cmd = str(tool_input.get("command") or "")
    try:
        c = shell.read(cmd, cwd)
    except Exception:
        return _UNREADABLE
    for argv in c.programs:
        program = os.path.basename(argv[0])
        if program == "jevguard":
            sub = next((a for i, a in enumerate(argv[1:], 1) if not a.startswith("-") and argv[i - 1] != "--settings"), "")
            if sub in _ADMIN:
                return f"the command runs `jevguard {sub}`"
        if program == "claude" and "config" in argv[1:3]:
            return "the command runs `claude config`, which changes Claude Code settings"
    admin = _ADMIN_TEXT.search(cmd)
    if admin:
        return (f"the text of the command contains `{' '.join(admin.group(0).split())[:70]}`, "
                "which reads like a jevguard administration command")
    written = next((p for p in sorted(shell.written_paths(c)) if protected(p)), None)
    if written:  # -o/path, --output-dir with -O, cd there and download, cp -t, dd of=
        return f"the command writes to {_show(written)}, {kind(written)}"
    for argv, dirs, paths, globs, fed in zip(c.programs, c.program_dirs, c.program_paths, c.program_globs,
                                             c.program_fed):
        program = os.path.basename(argv[0])
        if fed:  # xargs, $(...): what this program is given is named elsewhere in the command, if at all
            paths, globs = c.paths, c.globs
        if program == "jevguard":
            # Its other subcommands change nothing; of their arguments only real paths count
            # (`jevguard scan <file>`), not words like "status" resolved against the directory.
            paths = {p for a in argv[1:] if "/" in a or a.startswith("~") for p in shell.resolve(a, dirs)}
        elif not _reads_only(argv):
            inside = next((d for d in dirs for r in [*roots, released] if under(d, r)), None)
            if inside:  # `git reset --hard` there names no file and changes them all
                own = any(under(inside, r) for r in roots)
                return f"`{program}` runs inside {_show(inside)}, " + \
                    ("one of the guard's own directories" if own else kind(inside))
        # The guard's own directories hold the API key and the release list: any program counts.
        hit = next((p for p in sorted(paths) if any(under(p, r) for r in roots)), None) or \
            next((g for g in globs if any(shell.glob_reaches(g, r) for r in roots)), None)
        if hit:
            return f"`{program}` {_names(argv, hit)} {_show(hit)}, {kind(hit)}"
        if _reads_only(argv):
            continue  # cat .claude/settings.json, cat a released original, ls ~: looking is not a change
        hit = next((p for p in sorted(paths) if _SETTINGS.search(p) or under(p, released)), None) or \
            next((g for g in globs if _settings_glob(g) or shell.glob_reaches(g, released)), None)
        if hit:
            return f"`{program}` {_names(argv, hit)} {_show(hit)}, {kind(hit)}"
        # also any project's .claude directory: unpacking or copying into it can plant a settings file
        hit = next((p for p in sorted(paths) if above(p) or os.path.basename(p) == ".claude"), None) or \
            next((g for g in globs if any(shell.glob_reaches_above(g, t) for t in targets)), None)
        if hit:
            return (f"`{program}` {_names(argv, hit)} {_show(hit)}, a directory that holds the guard's files "
                    "or Claude Code settings, and it is not a program that only reads")
    return ""


def _show(path: str) -> str:
    home = os.path.expanduser("~")
    return "~" + path[len(home):] if path != home and under(path, home) else path


def _names(argv: list[str], hit: str) -> str:
    """Whether the path is an argument of its own or sits inside a longer text (a script passed
    to python, a here-document): the second is where false alarms come from."""
    leaf = os.path.basename(hit.rstrip("/"))
    direct = any(leaf in a and len(a) <= 300 and not re.search(r"\s", a) for a in argv[1:])
    return "is given" if direct else "is given a text that mentions"
