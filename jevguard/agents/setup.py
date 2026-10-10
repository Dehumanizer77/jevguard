"""Putting the guard's hooks into an agent's own settings, and taking them out again.

Claude Code's are handled in cli.py, as before. Each of the others gets a file of its own for
the guard where the agent allows one, so that nothing the owner wrote is touched; Cursor and
Codex keep all hooks in one file, and there the guard's entries are added to what is in it.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HOOK = str(ROOT / "bin" / "jevguard-hook")
AGENTS = ("claude", "grok", "copilot", "cursor", "codex", "hermes")


def _write(path: Path, content: dict | None) -> str:
    if content is None:
        if not path.exists():
            return "no change"
        path.unlink()
        return f"removed {path}"
    text = json.dumps(content, indent=2) + "\n"
    if path.exists() and path.read_text() == text:
        return "no change"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return f"wrote {path}"


def _merge(path: Path, events: dict, ours, remove: bool, top: dict | None = None) -> str:
    """Add the guard's entries to a hooks file that may hold the owner's own, or take them out.
    events: {event name: the entry to add}; ours(entry): the entry is the guard's."""
    settings = json.loads(path.read_text()) if path.exists() else {}
    before = json.dumps(settings, sort_keys=True)
    hooks = settings.setdefault("hooks", {})
    for event, entry in events.items():
        entries = [e for e in hooks.get(event, []) if not ours(e)]
        if not remove:
            entries.append(entry)
        if entries:
            hooks[event] = entries
        else:
            hooks.pop(event, None)
    if not hooks:
        settings.pop("hooks")
    elif top:
        for key, value in top.items():
            settings.setdefault(key, value)
    if json.dumps(settings, sort_keys=True) == before:
        return "no change"
    if not settings or settings == (top or {}):
        path.unlink(missing_ok=True)
        return f"removed {path}"
    if path.exists():
        shutil.copy2(path, path.with_name(path.name + ".jevguard.bak"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(settings, indent=2) + "\n")
    return f"updated {path}"


def grok(remove: bool) -> str:
    """~/.grok/hooks/jevguard.json. No matcher: Grok's MCP tools carry no common prefix to match
    on. Grok also runs the hook from Claude Code's settings; with this file there, that run
    stands back (see agents/grok.py)."""
    def entry(timeout: int) -> list:
        return [{"hooks": [{"type": "command", "command": f"{HOOK} --agent grok", "timeout": timeout}]}]
    content = None if remove else {"hooks": {"PreToolUse": entry(15), "PostToolUse": entry(60)}}
    return _write(Path.home() / ".grok" / "hooks" / "jevguard.json", content)


def copilot(remove: bool) -> str:
    def entry(timeout: int) -> list:
        return [{"type": "command", "bash": f"{HOOK} --agent copilot", "timeoutSec": timeout}]
    content = None if remove else {"version": 1, "hooks": {"preToolUse": entry(15), "postToolUse": entry(60)}}
    return _write(Path.home() / ".copilot" / "hooks" / "jevguard.json", content)


def cursor(remove: bool) -> str:
    command = f"{HOOK} --agent cursor"
    events = ("preToolUse", "postToolUse", "beforeShellExecution", "beforeMCPExecution", "beforeReadFile")
    return _merge(Path.home() / ".cursor" / "hooks.json", {e: {"command": command, "timeout": 60} for e in events},
                  lambda e: e.get("command") == command, remove, {"version": 1})


def codex(remove: bool) -> str:
    """~/.codex/hooks.json. Codex runs a hook only once the owner has reviewed it: it shows new
    hooks for review when it starts. Automation that has vetted them itself passes
    --dangerously-bypass-hook-trust."""
    command = f"{HOOK} --agent codex"
    group = {"hooks": [{"type": "command", "command": command, "timeout": 60}]}
    done = _merge(Path.home() / ".codex" / "hooks.json", {"PreToolUse": group, "PostToolUse": group},
                  lambda g: any(h.get("command") == command for h in g.get("hooks", [])), remove)
    return done if remove or done == "no change" else done + "; Codex will ask you to review the new hooks when it next starts"


def hermes(remove: bool) -> str:
    target = Path.home() / ".hermes" / "plugins" / "jevguard"
    if remove:
        if not target.exists():
            return "no change"
        shutil.rmtree(target)
        return f"removed {target}"
    shutil.copytree(ROOT / "integrations" / "hermes" / "jevguard", target, dirs_exist_ok=True)
    (target / "root").write_text(str(ROOT) + "\n")
    return f"wrote {target}; now run `hermes plugins enable jevguard` and restart Hermes"


def install(agent: str, remove: bool = False) -> str:
    return {"grok": grok, "copilot": copilot, "cursor": cursor, "codex": codex, "hermes": hermes}[agent](remove)


_FILES = {"grok": ".grok/hooks/jevguard.json", "copilot": ".copilot/hooks/jevguard.json",
          "cursor": ".cursor/hooks.json", "codex": ".codex/hooks.json"}


def _holds(node, command: str) -> bool:
    if isinstance(node, dict):
        return any(_holds(v, command) for v in node.values())
    if isinstance(node, list):
        return any(_holds(v, command) for v in node)
    return node == command


def installed(agent: str) -> bool:
    """The agent's settings start the hook of this checkout. For `jevguard status`; whether the
    agent has loaded them (Codex: reviewed them) only the agent can say."""
    try:
        if agent == "hermes":
            return (Path.home() / ".hermes" / "plugins" / "jevguard" / "root").read_text().strip() == str(ROOT)
        return _holds(json.loads((Path.home() / _FILES[agent]).read_text()), f"{HOOK} --agent {agent}")
    except (OSError, ValueError):
        return False
