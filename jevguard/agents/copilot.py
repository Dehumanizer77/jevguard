"""GitHub Copilot CLI. From its hooks reference as read on 2026-10-10
(docs.github.com/en/copilot/reference/copilot-cli-reference/cli-hooks-reference).
NOT RUN AGAINST COPILOT: it is not installed where this was written.

Hooks are JSON files in ~/.copilot/hooks/. With camelCase event names (preToolUse, postToolUse)
the input is camelCase and carries no event name:

    before:  {sessionId, timestamp, cwd, toolName, toolArgs}
    after:   the same, and toolResult: {resultType, textResultForLlm}

Tools: bash {command}, view / create / edit {path}, grep, glob, web_fetch {url}, powershell,
task, ask_user. The reference does not give the argument names or how MCP tools are named, so
the adapter takes the usual ones and treats a tool it does not know as bringing outside content.

A postToolUse hook replaces the result (modifiedResult), a preToolUse hook can ask
(permissionDecision "ask") and rewrite the arguments (modifiedArgs). A preToolUse hook that
fails denies the call; a postToolUse hook that fails changes nothing.
"""

from __future__ import annotations

import json

from .. import engine
from ..engine import Call, Decision
from . import Agent

_TOOLS = {"bash": "Bash", "powershell": "Bash", "view": "Read", "grep": "Grep", "glob": "Grep", "web_fetch": "WebFetch",
          "web_search": "WebSearch", "create": "Write", "edit": "Edit"}
_LOCAL = {"task", "ask_user", "report_intent", "update_todo"}  # bring nothing in from outside


class Copilot(Agent):
    name, title = "copilot", "Copilot"

    def read(self, d: dict) -> tuple[str, Call] | None:
        native = str(d.get("toolName") or "")
        if not native:
            return None
        args = d.get("toolArgs")
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except ValueError:
                args = {}
        args = args if isinstance(args, dict) else {}
        tool = _TOOLS.get(native) or (native if native in _LOCAL else "mcp__" + native)
        tool_input = dict(args)
        if isinstance(args.get("command"), str):
            tool_input["command"] = engine.without_own_lines(args["command"])
        path = args.get("path") or args.get("file_path") or args.get("filePath")
        if path and tool in ("Read", "Grep", "Edit", "Write"):
            tool_input["file_path" if tool != "Grep" else "path"] = path
        call = Call(tool, tool_input, str(d.get("sessionId") or ""), str(d.get("cwd") or ""),
                    {"client": self.name, "native_tool": native}, self.title)
        call.given = args
        if "toolResult" not in d:
            return "before", call
        call.raw = d.get("toolResult")
        call.text = str((call.raw or {}).get("textResultForLlm") or "") if isinstance(call.raw, dict) else str(call.raw or "")
        return "after", call

    def answer(self, d: dict, phase: str, call: Call, decision: Decision) -> dict | None:
        if decision.action == "replace":
            return {"modifiedResult": {"resultType": "success", "textResultForLlm": decision.notice}}
        out = {"permissionDecision": "ask", "permissionDecisionReason": f"jevguard: {decision.reason}"}
        if call.tool == "Bash" and decision.topic and isinstance(call.tool_input.get("command"), str):
            command = engine.with_question(call.tool_input["command"], decision, call.given.get("description") or "", self.title)
            out["modifiedArgs"] = {**call.given, "command": command}
        return out


AGENT = Copilot()
