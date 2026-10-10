"""Codex CLI (OpenAI). Checked against codex 0.160.0 on 2026-10-10: its hooks page
(learn.chatgpt.com/docs/hooks), the hooks source in its repository (codex-rs/hooks), the input
its hooks really receive, and tests/e2e_codex.py against the live program.

Hooks are in ~/.codex/hooks.json (or [hooks] in config.toml), in Claude Code's form. Codex runs
a hook only once the owner has reviewed it (`/hooks`; it shows new ones when it starts), or
with --dangerously-bypass-hook-trust in automation. The input has Claude Code's form too:

    before:  {hook_event_name: "PreToolUse", session_id, cwd, tool_name: "Bash", tool_input: {command}, ...}
    after:   the same with tool_response, which for the shell is the plain text it printed

What a hook may answer is narrower than the schema suggests:

- After a call there is no field for a replacement (updatedMCPToolOutput is "parsed but not
  supported yet"). But on `decision: "block"` Codex "records the feedback, replaces the tool
  result with it, and continues the model from the hook's message". So the notice goes out as
  that feedback, for any tool, and the model gets it in place of the result. The hook runs
  outside Codex's sandbox, so this works whatever the sandbox allows the command itself.
- Before a call, "ask" is not supported yet (the call would simply run). Where the guard would
  ask, the call is refused with the reason, and the owner can run it himself.
"""

from __future__ import annotations

from .. import engine, toolio
from ..engine import Call, Decision
from . import Agent

_SHELL = {"Bash", "shell", "local_shell", "exec_command", "unified_exec"}


class Codex(Agent):
    name, title = "codex", "Codex"

    def read(self, d: dict) -> tuple[str, Call] | None:
        event = d.get("hook_event_name")
        if event not in ("PreToolUse", "PostToolUse"):
            return None
        native = str(d.get("tool_name") or "")
        given = d.get("tool_input") if isinstance(d.get("tool_input"), dict) else {}
        tool = "Bash" if native in _SHELL else {"apply_patch": "Edit"}.get(native, native)
        tool_input = dict(given)
        if isinstance(given.get("command"), str) and tool == "Bash":
            tool_input["command"] = engine.without_own_lines(given["command"])
        call = Call(tool, tool_input, str(d.get("session_id") or ""), str(d.get("cwd") or ""),
                    {"tool_use_id": d.get("tool_use_id"), "client": self.name, "native_tool": native}, self.title)
        if event == "PreToolUse":
            return "before", call
        call.raw = d.get("tool_response")
        call.text, call.images = toolio.text_of("", call.raw)
        return "after", call

    def answer(self, d: dict, phase: str, call: Call, decision: Decision) -> dict | None:
        if decision.action == "replace":
            return {"decision": "block", "reason": decision.notice}
        return {"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "deny",
            "permissionDecisionReason": f"jevguard: {decision.reason} Codex cannot be made to ask the owner, "
                                        "so the call was not run; the owner can run it himself."}}


AGENT = Codex()
