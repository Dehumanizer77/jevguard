"""Actions that could carry out an injected instruction: sending data out, publishing, and
writing to files that run later. No model here, only patterns; the detector can miss an
injection, and this is the layer that still stands when it does."""

from __future__ import annotations

import os
import re

_SEND = [
    (re.compile(r"\b(?:curl|wget|xh|https?)\b[^|;&\n]*(?:\s-(?:d|F|T)\b|--data\b|--data-\w+|--form\b|"
                r"--upload-file\b|--post-(?:data|file)\b|--body-(?:data|file)\b|"
                r"-X\s*(?:POST|PUT|PATCH|DELETE)\b|--request[=\s]+(?:POST|PUT|PATCH|DELETE)\b)", re.I),
     "sends data with an HTTP request"),
    (re.compile(r"\bgit\s+(?:-\S+\s+)*push\b"), "git push"),
    (re.compile(r"\bgh\s+(?:pr|issue|release|gist|repo|secret|variable|workflow|api)\b[^|;&\n]*"
                r"\b(?:create|comment|edit|merge|close|delete|upload|set|run|fork|"
                r"-X\s*(?:POST|PUT|PATCH|DELETE)|-f\b|--field\b|--raw-field\b|--input\b)"), "changes something on GitHub"),
    (re.compile(r"(?:^|[\s;|&(])(?:ssh|scp|sftp|rsync|ftp|nc|ncat|netcat|socat|telnet)\s"), "opens a connection to another machine"),
    (re.compile(r"(?:^|[\s;|&(])(?:mail|mailx|sendmail|msmtp|mutt|swaks)\s|\bhimalaya\b[^|;&\n]*\b(?:send|write|reply|forward)\b"),
     "sends mail"),
    (re.compile(r"\b(?:npm|pnpm|yarn)\s+publish\b|\btwine\s+upload\b|\bcargo\s+publish\b|\bdocker\s+push\b"), "publishes a package"),
    (re.compile(r"\bcrontab\b|\bsystemctl\s+(?:--user\s+)?(?:enable|start|restart)\b"), "schedules or starts a service"),
]
_MCP_WRITE = re.compile(r"(?:^|_)(?:send|create|update|delete|post|write|reply|upload|share|publish|batch|"
                        r"move|remove|add|insert|modify|forward|draft|edit|set|invite|comment)(?:_|$)", re.I)
# Files that run or grant access later.
_STARTUP = re.compile(r"(?:^|/)(?:\.ssh/|\.claude/(?:settings[^/]*\.json|hooks/|CLAUDE\.md)|\.config/jevguard/|"
                      r"\.git/hooks/|\.bashrc$|\.bash_profile$|\.profile$|\.zshrc$|\.gitconfig$|"
                      r"\.config/systemd/|\.config/autostart/|CLAUDE\.md$|\.mcp\.json$)")
_LONG_URL = 300  # a fetch can carry data out in its address


def risky(tool: str, tool_input: dict) -> str:
    """Why this call could act on an injected instruction, or an empty string."""
    if tool == "Bash":
        cmd = str(tool_input.get("command") or "")
        for pattern, why in _SEND:
            if pattern.search(cmd):
                return why
        return ""
    if tool == "WebFetch":
        url = str(tool_input.get("url") or "")
        return "fetches a very long address, which can carry data out" if len(url) > _LONG_URL else ""
    if tool in ("Write", "Edit", "NotebookEdit"):
        path = os.path.normpath(os.path.expanduser(str(tool_input.get("file_path") or "")))
        return "writes to a file that runs or grants access later" if _STARTUP.search(path) else ""
    if tool.startswith("mcp__"):
        name = tool.rsplit("__", 1)[-1]
        return "MCP tool that changes or sends something" if _MCP_WRITE.search(name) else ""
    return ""
