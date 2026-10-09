"""Where a tool result came from. Content is judged by its origin, not by the tool that read it.

"external": web pages, search results, MCP tools, commands that fetch from a public address,
            files those commands saved, files under the configured external paths, and whatever
            a command or a search reads back out of those files.
"local":    files on this machine and output of local commands.
"warn":     output of commands that only report on the agent's own work; never blocked.
None:       not scanned at all.
"""

from __future__ import annotations

import ipaddress
import os
import re

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
        tail = "/" if os.path.isdir(root) else ""
        if root + tail in text or (under(root, home) and root != home and "~" + root[len(home):] + tail in text):
            return True
        for base in bases:
            if base and root != base and under(root, base):
                rel = root[len(base.rstrip("/")) + 1:] + tail
                if len(rel) > 2 and rel in text and re.search(r"(?<![\w.-])" + re.escape(rel) + (r"(?![\w-])" if not tail else ""), text):
                    return True
    return False


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
    if any(len(os.path.basename(p)) >= 5 and os.path.basename(p) in cmd for p in session_paths):
        return True  # named in a way the reader did not resolve
    if session_paths and c.dynamic:
        return True
    return mentions(output, roots, c.dirs)


def classify(tool: str, tool_input: dict, cfg, cwd: str, session_paths: list[str], output: str = "") -> str | None:
    """output is the text of the result: a search over local directories that returns lines from
    an outside file is outside content, and only the result shows that."""
    if _matches(tool, cfg.skip_tools):
        return None
    if _matches(tool, cfg.warn_tools):
        return "warn"
    if tool in ("WebFetch", "WebSearch") or tool.startswith("mcp__"):
        if tool == "WebFetch" and not cfg.scan_private_hosts:
            m = _URL.match(str(tool_input.get("url") or ""))
            if m and private_host(m.group(1)):
                return "local"
        return "external"
    roots = outside_roots(cfg, session_paths)
    if tool == "Bash":
        cmd = str(tool_input.get("command") or "")
        if fetches_outside(cmd, cfg.scan_private_hosts) or _bash_reads_outside(cmd, cwd, roots, session_paths, output):
            return "external"
        return "warn" if trusted_command(cmd, set(cfg.trusted_commands)) else "local"
    if tool in ("Read", "Grep"):
        base = canonical(cwd) if cwd else ""
        path = canonical(str(tool_input.get("file_path") or tool_input.get("path") or cwd or "/"), cwd)
        if any(under(path, r) for r in roots):
            return "external"
        if tool == "Grep" and mentions(output, roots, [path, base]):
            return "external"
        return "local"
    return None  # tools that carry no outside content, and tools this list does not know
