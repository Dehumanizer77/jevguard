"""Grok Build (xAI). Checked against grok 1.0.30 on 2026-10-10: its bundled user guide
(10-hooks.md) and the input its hooks really receive.

Grok runs the hooks of ~/.claude/settings.json as well as its own (~/.grok/hooks/*.json), so
the hook Claude Code uses is started by Grok too. The input has Claude's snake_case keys and
Grok's camelCase ones side by side, but the tools carry Grok's names and their results Grok's
shapes:

    run_terminal_command  {command, description}   -> {"type": "Bash", "output": [bytes],
                                                        "output_for_prompt": "...", "output_file": path, ...}
    read_file             {target_file}             -> {"type": "ReadFile", "FileContent": {content, raw_output, ...}}
    grep                  {pattern, path}           -> {"type": "GrepSearch", "stdout": [bytes], ...}
    list_dir              {target_directory}        -> {"type": "ListDir", "Content": {content, absolute_root_path}}
    web_fetch             {url}                     -> {"type": "WebFetch", "Content": {url, content, content_type, ...}}
    <server>__<tool>      an MCP tool               -> whatever the server returned

A PostToolUse hook replaces the model's copy of any result (updatedToolOutput). For a built-in
tool the replacement has to be the tool's own tagged object, or Grok ignores it and the original
stands; so the result is handed back with its text swapped, not rebuilt. A PreToolUse hook can
ask (permissionDecision "ask") and rewrite the input (updatedInput), as in Claude Code.
"""

from __future__ import annotations

import os

from .. import engine
from ..engine import Call, Decision
from . import Agent

NATIVE_HOOKS = os.path.join("~", ".grok", "hooks", "jevguard.json")
_TOOLS = {"run_terminal_command": "Bash", "read_file": "Read", "grep": "Grep", "list_dir": "Grep",
          "web_fetch": "WebFetch", "web_search": "WebSearch", "search_replace": "Edit", "write_file": "Write"}
# Fields of a result that repeat the call (kept as they are, and not text the model is given to
# read), and fields that point at a copy of the original output (emptied in a replacement).
_ECHO = {"type", "command", "description", "current_dir", "absolute_path", "absolute_root_path", "url",
         "content_type", "pattern", "path", "query", "target_file", "target_directory"}
_POINTERS = {"output_file"}


def _is_bytes(o) -> bool:
    return isinstance(o, list) and bool(o) and all(isinstance(x, int) and not isinstance(x, bool) and 0 <= x < 256 for x in o)


def _texts(o, out: list, key: str = "") -> None:
    if key in _ECHO or key in _POINTERS:
        return
    if isinstance(o, str):
        out.append(o)
    elif _is_bytes(o):
        out.append(bytes(o).decode("utf-8", "replace"))
    elif isinstance(o, dict):
        for k, v in o.items():
            _texts(v, out, k)
    elif isinstance(o, list):
        for v in o:
            _texts(v, out, key)


def text_of(result) -> str:
    """What the model would read of a result. The same text often stands in it two or three
    times (bytes and rendered, numbered and plain); a text contained in another is left out."""
    found: list = []
    _texts(result, found)
    found = sorted({t for t in found if t}, key=len, reverse=True)
    kept: list = []
    for t in found:
        if not any(t in longer for longer in kept):
            kept.append(t)
    return "\n".join(kept)


def replaced(result, notice: str, key: str = ""):
    """The result in its own shape with every text in it swapped for the notice: whichever field
    Grok renders for the model, that is what it finds there."""
    if key in _ECHO:
        return result
    if key in _POINTERS:
        return "" if isinstance(result, str) else result
    if isinstance(result, str):
        return notice
    if _is_bytes(result):
        return list(notice.encode())
    if isinstance(result, dict):
        return {k: replaced(v, notice, k) for k, v in result.items()}
    if isinstance(result, list):
        return [] if any(isinstance(v, (dict, list)) for v in result) else [notice] if result else []
    return result


class Grok(Agent):
    name, title = "grok", "Grok"

    def detect(self, d: dict, env) -> bool:
        if not (env.get("GROK_HOOK_EVENT") or "hookEventName" in d):
            return False
        # Started from Claude Code's settings while Grok has hooks of its own for the guard: those
        # do the work, with no matcher in the way, and this run would only do it a second time.
        if os.path.exists(os.path.expanduser(NATIVE_HOOKS)):
            raise SystemExit(0)
        return True

    def read(self, d: dict) -> tuple[str, Call] | None:
        event = d.get("hook_event_name")
        if event not in ("PreToolUse", "PostToolUse"):
            return None
        native = str(d.get("toolName") or d.get("tool_name") or "")
        given = d.get("toolInput") if isinstance(d.get("toolInput"), dict) else d.get("tool_input")
        given = given if isinstance(given, dict) else {}
        tool = _TOOLS.get(native) or ("mcp__" + native if "__" in native else native)
        tool_input = dict(given)
        if isinstance(given.get("command"), str):
            tool_input["command"] = engine.without_own_lines(given["command"])
        path = given.get("target_file") or given.get("file_path") or given.get("target_directory") or given.get("path")
        if path and tool in ("Read", "Grep", "Edit", "Write"):
            tool_input["file_path" if tool != "Grep" else "path"] = path
        call = Call(tool, tool_input, str(d.get("sessionId") or d.get("session_id") or ""), str(d.get("cwd") or ""),
                    {"tool_use_id": d.get("toolUseId") or d.get("tool_use_id"), "client": self.name, "native_tool": native},
                    self.title)
        call.given = given
        if event == "PreToolUse":
            return "before", call
        call.raw = d.get("toolResult", d.get("tool_response"))
        call.text = text_of(call.raw)
        return "after", call

    def answer(self, d: dict, phase: str, call: Call, decision: Decision) -> dict | None:
        if decision.action == "replace":
            # An MCP result has no shape to keep: a string becomes the text the model reads. So does
            # an oversized result, which reaches the hook as a plain string.
            mcp = call.tool.startswith("mcp__") or not isinstance(call.raw, dict)
            new = decision.notice if mcp else replaced(call.raw, decision.notice)
            return {"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": new}}
        out = {"hookEventName": "PreToolUse", "permissionDecision": "ask",
               "permissionDecisionReason": f"jevguard: {decision.reason}"}
        if call.tool == "Bash" and decision.topic and isinstance(call.tool_input.get("command"), str):
            command = engine.with_question(call.tool_input["command"], decision, call.given.get("description") or "", self.title)
            out["updatedInput"] = {**call.given, "command": command}  # Grok's own fields, or the rewrite fails its schema
        return {"hookSpecificOutput": out}


AGENT = Grok()
