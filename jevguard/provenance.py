"""Where a tool result came from. Content is judged by its origin, not by the tool that read it.

"external": web pages, search results, MCP tools, commands that fetch from a public address,
            files those commands saved, files under the configured external paths, and whatever
            a command or a search reads back out of those files.
"local":    files on this machine and output of local commands.
"trusted":  outside content from an address the owner put on the trusted list: scanned and
            logged like any other, never withheld.
"own":      what `gh` returns about the owner's own repositories: withheld only from a higher
            score up. "echo": the reply to a change the command itself made there; never withheld.
"local":    files on this machine and output of local commands.
"warn":     output of commands that only report on the agent's own work; never blocked.
None:       not scanned at all.
"""

from __future__ import annotations

import ipaddress
import os
import re
from urllib.parse import urlsplit

from . import shell
from .shell import canonical, under

# Commands that only ever talk to a remote service.
_REMOTE_TOOL = re.compile(r"(?:^|[\s;|&(])(?:rtk\s+)?(?:gh|himalaya|yt-dlp|lynx|w3m|notmuch)\b")
_URL = re.compile(r"\b(?:https?|wss?|ftp)://([^\s/'\"<>|;&)\\]+)", re.I)
_PRIVATE_SUFFIX = (".local", ".lan", ".home", ".internal", ".localdomain", ".home.arpa")

# Commands whose output only reports on the agent's own work. Every segment of a compound
# command must be one of these; command substitution never is. ls is not here: file names can
# come from outside.
_TRUSTED_CMDS = {"cd", "pwd", "echo", "printf", "which", "whoami", "id", "hostname", "date", "uptime",
                 "df", "du", "wc", "mkdir", "touch", "cp", "mv", "rm", "ln", "chmod", "true", "sleep"}
_TRUSTED_GIT = {"status", "add", "commit", "checkout", "switch", "branch", "stash", "rev-parse", "init",
                "restore", "tag"}

def private_host(host: str) -> bool:
    host = host.rsplit("@", 1)[-1].lower()
    if host.startswith("["):  # [::1]:8080
        host = host[1:].split("]", 1)[0]
    elif host.count(":") == 1:
        host = host.split(":", 1)[0]
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return host == "localhost" or "." not in host or host.endswith(_PRIVATE_SUFFIX)


_URL_FULL = re.compile(r"\b(?:https?|wss?|ftp)://[^\s'\"<>|;&)\\]+", re.I)
_DEFAULT_PORT = {"http": 80, "https": 443}


def _url_parts(url: str):
    """(scheme, host, port, path) of an http(s) address, or None for anything else or anything
    that does not parse cleanly: a backslash, a password part, an odd port. Those are how one
    address is made to look like another, and an address on the trusted list is not scored
    for blocking, so a doubtful one is simply not trusted."""
    if "\\" in url or any(ord(c) < 33 for c in url):
        return None
    try:
        u = urlsplit(url)
        port = u.port
    except ValueError:
        return None
    scheme = u.scheme.lower()
    if scheme not in _DEFAULT_PORT or not u.hostname or u.username is not None or u.password is not None:
        return None
    return scheme, u.hostname.lower().rstrip("."), port or _DEFAULT_PORT[scheme], u.path or "/"


def trusted_source(url: str, prefixes: list) -> bool:
    """The address lies under one of the trusted prefixes: same scheme, same host, same port, and
    its path is the prefix's path or below it. `https://docs.example.com/guide` covers
    `/guide` and `/guide/x`, not `/guide-2`, not `docs.example.com.evil.net`, not
    `docs.example.com@evil.net`."""
    target = _url_parts(url)
    if not target:
        return False
    for prefix in prefixes:
        base = _url_parts(str(prefix))
        if not base or base[:3] != target[:3]:
            continue
        root = base[3].rstrip("/")
        if "/../" in target[3] + "/" or "/./" in target[3] + "/" or "%" in target[3][:len(root) + 1]:
            continue  # a path that climbs out of the prefix, or hides a separator in an escape
        if target[3] == root or target[3].startswith(root + "/"):
            return True
    return False


def fetched_urls(cmd: str) -> list[str]:
    return [u.rstrip(".,") for u in _URL_FULL.findall(cmd)]


def fetches_outside(cmd: str, scan_private_hosts: bool = False) -> bool:
    """The command reads from a public address: a literal URL of a public host, or a tool that
    only talks to a remote service. A fetch whose address is not visible in the command (a
    variable, a script) counts as local: its output may be private data from this network."""
    hosts = _URL.findall(cmd)
    if any(scan_private_hosts or not private_host(h) for h in hosts):
        return True
    return bool(_REMOTE_TOOL.search(cmd))


def trusted_command(cmd: str, extra: set) -> bool:
    if not cmd.strip() or re.search(r"\$\(|`|<\(", cmd):
        return False
    cmd = re.sub(r"\d*>&\d+", " ", cmd)  # 2>&1 is a redirect, not a background job
    for seg in re.split(r"&&|\|\||[;|&\n]", cmd):
        words = seg.split()
        while words and re.fullmatch(r"\w+=\S*", words[0]):  # FOO=bar cmd
            words.pop(0)
        if words and words[0] == "rtk":
            words.pop(0)
        if not words:
            continue
        name = os.path.basename(words[0])
        if name == "git":
            sub = next((w for w in words[1:] if not w.startswith("-")), "")
            if sub not in _TRUSTED_GIT:
                return False
        elif name not in _TRUSTED_CMDS and name not in extra:
            return False
    return True


def saved_paths(cmd: str, cwd: str, track_clones: bool) -> list[str]:
    """Files written by a command that fetches from outside or reads an outside file: reading
    them later is reading outside content (see shell.written_paths for what is recognised).
    Not followed: an archive unpacked into the current directory, a name chosen by the server,
    and files a script writes on its own."""
    try:
        c = shell.read(cmd, cwd)
    except Exception:
        return []
    # A destination that is the working directory or above it would make the whole project
    # outside content on the strength of one command; that is not what the command says.
    return sorted(p for p in shell.written_paths(c, track_clones)
                  if not p.startswith("/dev/") and not any(under(d, p) for d in c.dirs))


def _matches(tool: str, patterns: list) -> bool:
    return any(re.fullmatch(p, tool) for p in patterns)


def outside_roots(cfg, session_paths: list[str]) -> list[str]:
    """Everything whose content counts as coming from outside: the configured directories, the
    quarantined originals and what this session downloaded. The rest of the guard's state (its
    log, counters, session records) holds no content from outside."""
    return [canonical(p) for p in cfg.external_paths] + [canonical(str(cfg.quarantine_dir))] + list(session_paths)


def mentions(text: str, roots: list[str], bases: list[str]) -> bool:
    """The text names an outside file or directory: by absolute path, or by its path relative to
    one of the bases (a search prints `sub/page.html:12:...` for what it found there)."""
    if not text:
        return False
    home = os.path.expanduser("~")
    for root in roots:
        # A directory counts when something inside it is named; its bare name in a listing does not.
        is_dir, is_file = os.path.isdir(root), os.path.isfile(root)
        tail = "/" if is_dir else ""
        if root + tail in text or (under(root, home) and root != home and "~" + root[len(home):] + tail in text):
            return True
        for base in bases:
            if not (base and root != base and under(root, base)):
                continue
            rel = root[len(base.rstrip("/")) + 1:]
            if rel not in text:
                continue
            # A relative name counts only where a listing or a search would print it: at the start
            # of a line, as `name:12:...`, `name-12-...`, `name/inside` or on a line of its own.
            # The same word in the middle of a sentence ("on branch main") is not that file.
            name = r"(?m)^\s*(?:\./)?" + re.escape(rel)
            as_file = re.search(name + r"(?:[:-]|\s*$)", text) if not is_dir else None
            as_dir = re.search(name + "/", text) if not is_file else None
            if as_file or as_dir:
                return True
    return False


_file_name = re.compile(r"[\w@%+-][\w@%+.-]{2,}\.[A-Za-z0-9]{1,8}")  # page.html, data-2.json; not "main" or "out"


def _bash_reads_outside(cmd: str, cwd: str, roots: list[str], session_paths: list[str], output: str) -> bool:
    """The command, as far as it can be read, takes its output from an outside file: it runs in an
    outside directory, names an outside file (directly, relatively, after `cd`, through a variable
    it set, by glob, or inside a quoted script), or prints one's name among its results. When the
    session has downloaded files and the command picks its files at run time, it counts too."""
    try:
        c = shell.read(cmd, cwd)
    except Exception:
        return True  # a command that cannot be read is not assumed to be local
    if any(c.names(r) for r in roots):
        return True
    if any(_file_name.fullmatch(os.path.basename(p)) and os.path.basename(p) in cmd for p in session_paths):
        return True  # named in a way the reader did not resolve; only for names that read as a file's
    if session_paths and c.dynamic:
        return True
    return mentions(output, roots, c.dirs)


_OTHER_REMOTE = {"himalaya", "yt-dlp", "lynx", "w3m", "notmuch"}


def _own_repo_mode(cmd: str, cwd: str, cfg) -> str | None:
    """"own" when the only thing the command fetches is `gh` output about the owner's own
    repositories; "echo" when all of it is the reply to a change the command itself made there
    (gh pr create, gh api -X PATCH); None when anything about the command is not plain: another
    remote tool, a repository that cannot be told, a value computed at run time."""
    if "GH_REPO" in cmd or "GH_HOST" in cmd:
        return None
    try:
        c = shell.read(cmd, cwd)
    except Exception:
        return None
    programs = [(os.path.basename(argv[0]), argv, dirs) for argv, dirs in zip(c.programs, c.program_dirs)]
    calls = [(argv, dirs) for name, argv, dirs in programs if name == "gh"]
    if not calls or c.dynamic or any(name in _OTHER_REMOTE for name, _, _ in programs):
        return None
    from . import gate, github
    for argv, dirs in calls:
        repos = github.gh_repos(argv, dirs)
        if not repos or not all(github.is_own(r, cfg.own_repos) for r in repos):
            return None
    return "echo" if all(gate._gh_changes(argv[1:]) for argv, _ in calls) else "own"


def classify(tool: str, tool_input: dict, cfg, cwd: str, session_paths: list[str], output: str = "") -> str | None:
    """output is the text of the result: a search over local directories that returns lines from
    an outside file is outside content, and only the result shows that."""
    if _matches(tool, cfg.skip_tools):
        return None
    if _matches(tool, cfg.warn_tools):
        return "warn"
    if tool in ("WebFetch", "WebSearch") or tool.startswith("mcp__"):
        if tool == "WebFetch":
            url = str(tool_input.get("url") or "")
            m = _URL.match(url)
            if m and private_host(m.group(1)) and not cfg.scan_private_hosts:
                return "local"
            if trusted_source(url, cfg.trusted_sources):
                return "trusted"
        return "external"
    roots = outside_roots(cfg, session_paths)
    if tool == "Bash":
        cmd = str(tool_input.get("command") or "")
        if _bash_reads_outside(cmd, cwd, roots, session_paths, output):
            return "external"
        if fetches_outside(cmd, cfg.scan_private_hosts):
            # Trusted only if every public address the command names is on the list and nothing in
            # it talks to a service whose address is not in the command (gh, ...).
            public = [u for u in fetched_urls(cmd)
                      if cfg.scan_private_hosts or not private_host(_URL.match(u).group(1))]
            if public and not _REMOTE_TOOL.search(cmd) and all(trusted_source(u, cfg.trusted_sources) for u in public):
                return "trusted"
            if not public and cfg.own_repos:
                return _own_repo_mode(cmd, cwd, cfg) or "external"
            return "external"
        return "warn" if trusted_command(cmd, set(cfg.trusted_commands)) else "local"
    if tool in ("Read", "Grep"):
        base = canonical(cwd) if cwd else ""
        path = canonical(str(tool_input.get("file_path") or tool_input.get("path") or cwd or "/"), cwd)
        if any(under(path, r) for r in roots):
            return "external"
        if tool == "Grep" and mentions(output, roots, [path, base]):
            return "external"
        if tool == "Read" and under(path, canonical(str(cfg.released_dir))):
            return None  # an original the owner read and released: not scanned a second time
        return "local"
    return None  # tools that carry no outside content, and tools this list does not know
