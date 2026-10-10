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
import re

from .. import engine, toolio
from ..engine import Call, Decision
from . import Agent

NATIVE_HOOKS = os.path.join("~", ".grok", "hooks", "jevguard.json")
_TOOLS = {"run_terminal_command": "Bash", "read_file": "Read", "grep": "Grep", "list_dir": "Grep",
          "web_fetch": "WebFetch", "web_search": "WebSearch", "search_replace": "Edit", "write_file": "Write"}
# A built-in tool's result repeats parts of the call beside what the tool brought in (the command,
# its description, the address), carries its own tag, and may point at a copy of the output. Those
# are not text to scan and stay as they are in a replacement. But a field is taken for one of them
# by its value, never by its name: the tag has to be one of Grok's tags, a repeat has to say what
# the call said. The first version went by the name, and any result with a field called
# "description" or "url" had that field passed over.
_TAG = re.compile(r"[A-Za-z]{1,30}")  # "Bash", "ReadFile", "GrepSearch", "ListDir", "WebFetch": one word
_POINTER = "output_file"  # where Grok keeps the whole output; emptied in a replacement
_MEDIA_TYPE = re.compile(r"(?:text|image|audio|video|application|font|model|multipart|message)/[A-Za-z0-9.+-]{1,60}"
                         r"(?:;\s*charset=[A-Za-z0-9._-]{1,30})?")


def _is_bytes(o) -> bool:
    return isinstance(o, list) and bool(o) and all(isinstance(x, int) and not isinstance(x, bool) and 0 <= x < 256 for x in o)


def said_by(given: dict, cwd: str) -> frozenset:
    """What the call itself said, in the forms a result repeats it: its arguments, the directory
    it ran in, and its paths made absolute."""
    said = {cwd} if cwd else set()
    for value in given.values():
        if isinstance(value, str) and value:
            said.add(value)
            if not re.search(r"\s", value):
                full = os.path.join(cwd, os.path.expanduser(value))
                said.update((os.path.normpath(full), os.path.realpath(full)))
    return frozenset(said)


def _not_content(value: str, key: str, top: bool, said: frozenset) -> bool:
    if top and key == "type":
        return bool(_TAG.fullmatch(value))
    if key == "content_type":  # "text/html; charset=utf-8": the server's, and a media type or it is text
        return bool(_MEDIA_TYPE.fullmatch(value))
    if top and key == _POINTER:
        return not re.search(r"\s", value)  # a path
    return value in said


def _texts(o, out: list, said: frozenset, key: str = "", depth: int = 0) -> None:
    if isinstance(o, str):
        if not _not_content(o, key, depth == 1, said):
            out.append(o)
    elif _is_bytes(o):
        out.append(bytes(o).decode("utf-8", "replace"))
    elif isinstance(o, dict):
        for k, v in o.items():
            _texts(v, out, said, k, depth + 1)
    elif isinstance(o, list):
        for v in o:
            _texts(v, out, said, key, depth)


def text_of(result, said: frozenset = frozenset()) -> str:
    """What the model would read of a built-in tool's result. The same text often stands in it
    two or three times (bytes and rendered, numbered and plain); a text contained in another is
    left out."""
    found: list = []
    _texts(result, found, said)
    found = sorted({t for t in found if t}, key=len, reverse=True)
    kept: list = []
    for t in found:
        if not any(t in longer for longer in kept):
            kept.append(t)
    return "\n".join(kept)


def replaced(result, notice: str, said: frozenset = frozenset(), key: str = "", depth: int = 0):
    """The result in its own shape with every text in it swapped for the notice: whichever field
    Grok renders for the model, that is what it finds there."""
    if isinstance(result, str):
        if depth == 1 and key == _POINTER:
            return ""
        return result if _not_content(result, key, depth == 1, said) else notice
    if _is_bytes(result):
        return list(notice.encode())
    if isinstance(result, dict):
        return {k: replaced(v, notice, said, k, depth + 1) for k, v in result.items()}
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
        call.given, call.shaped, call.said = given, False, frozenset()
        if event == "PreToolUse":
            return "before", call
        call.raw = d.get("toolResult", d.get("tool_response"))
        # Only a built-in tool's own result is read by its shape, and handed back in it. Anything
        # else (an MCP server's result, whatever it calls its fields or itself) is read whole.
        call.shaped = native in _TOOLS and isinstance(call.raw, dict)
        if call.shaped:
            call.said = said_by(given, call.cwd)
            call.text = text_of(call.raw, call.said)
        else:
            call.text, call.images = toolio.text_of("", call.raw)
        return "after", call

    def answer(self, d: dict, phase: str, call: Call, decision: Decision) -> dict | None:
        if decision.action == "replace":
            # An MCP result has no shape to keep: a string becomes the text the model reads. So does
            # an oversized result, which reaches the hook as a plain string.
            new = replaced(call.raw, decision.notice, call.said) if call.shaped else decision.notice
            return {"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": new}}
        out = {"hookEventName": "PreToolUse", "permissionDecision": "ask",
               "permissionDecisionReason": f"jevguard: {decision.reason}"}
        if call.tool == "Bash" and decision.topic and isinstance(call.tool_input.get("command"), str):
            command = engine.with_question(call.tool_input["command"], decision, call.given.get("description") or "", self.title)
            out["updatedInput"] = {**call.given, "command": command}  # Grok's own fields, or the rewrite fails its schema
        return {"hookSpecificOutput": out}


AGENT = Grok()
