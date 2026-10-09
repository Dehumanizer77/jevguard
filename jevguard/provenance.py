"""Where a tool result came from. Content is judged by its origin, not by the tool that read it.

"external": web pages, search results, MCP tools, commands that fetch from a public address,
            files those commands saved, files under the configured external paths.
"local":    files on this machine and output of local commands.
"warn":     output of commands that only report on the agent's own work; never blocked.
None:       not scanned at all.
"""

from __future__ import annotations

import ipaddress
import os
import re

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

_OUT_ARG = re.compile(r"(?:^|\s)(?:-o|-O|--output|--output-document|-P|--directory-prefix)(?:=|\s+)"
                      r"(['\"]?)([^\s'\";|&<>]+)\1")
_REDIRECT = re.compile(r"(?:>>?|\|\s*tee(?:\s+-a)?)\s*(['\"]?)([^\s'\";|&<>]+)\1")
_CLONE = re.compile(r"\bgit\s+(?:-\S+\s+)*clone\b([^;|&\n]*)")


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


def norm_path(p: str, base: str = "") -> str:
    p = os.path.expanduser(p.strip().strip("'\""))
    if base and not os.path.isabs(p):
        p = os.path.join(base, p)
    return os.path.normpath(p)


def under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def saved_paths(cmd: str, cwd: str, track_clones: bool) -> list[str]:
    """Paths a fetching command writes (curl -o, wget -O/-P, > file, | tee file, git clone dir):
    reading them later is reading outside content."""
    out = []
    for m in list(_OUT_ARG.finditer(cmd)) + list(_REDIRECT.finditer(cmd)):
        target = m.group(2)
        if target.startswith(("/dev/", "&")):
            continue
        if re.match(r"https?://", target, re.I):  # curl -O URL: saved under the URL's file name
            target = target.split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1]
            if not target:
                continue
        out.append(norm_path(target, cwd))
    if track_clones:
        for m in _CLONE.finditer(cmd):
            args = [a.strip("'\"") for a in m.group(1).split() if not a.startswith("-")]
            if not args:
                continue
            repo = args[0]
            dest = args[1] if len(args) > 1 else re.sub(r"\.git$", "", repo.rstrip("/").rsplit("/", 1)[-1])
            if dest:
                out.append(norm_path(dest, cwd))
    return out


def _matches(tool: str, patterns: list) -> bool:
    return any(re.fullmatch(p, tool) for p in patterns)


def classify(tool: str, tool_input: dict, cfg, cwd: str, session_paths: list[str]) -> str | None:
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
    if tool == "Bash":
        cmd = str(tool_input.get("command") or "")
        if fetches_outside(cmd, cfg.scan_private_hosts) or str(cfg.state_dir) in cmd:
            return "external"
        return "warn" if trusted_command(cmd, set(cfg.trusted_commands)) else "local"
    if tool in ("Read", "Grep"):
        raw = str(tool_input.get("file_path") or tool_input.get("path") or "")
        if not raw:
            return "local"
        path = norm_path(raw, cwd)
        roots = [norm_path(p) for p in cfg.external_paths] + [str(cfg.state_dir)] + list(session_paths)
        return "external" if any(under(path, r) for r in roots) else "local"
    return None  # tools that carry no outside content, and tools this list does not know
