"""Cursor's agent. From its hooks page as read on 2026-10-10 (cursor.com/docs/agent/hooks).
NOT RUN AGAINST CURSOR: it is not installed where this was written.

Hooks are listed in ~/.cursor/hooks.json, one list per event. Every input carries
conversation_id, hook_event_name and workspace_roots. What each event allows decides what the
guard does there:

    preToolUse            {tool_name: "Shell", tool_input: {command, working_directory}}
                          may rewrite the input (updated_input); "ask" is accepted but not enforced.
                          The guard rewrites a shell command to run through `jevguard-run`, because
                          nothing later can replace what it printed.
    beforeShellExecution  {command, cwd}            may answer permission: allow | deny | ask
                          The gate asks here.
    beforeMCPExecution    {tool_name, tool_input}   the same
    beforeReadFile        {file_path, content}      may answer permission: allow | deny
                          The file's content is scanned before the model gets it; a file that
                          scores as an injection is refused.
    postToolUse           {tool_name, tool_input, tool_output}
                          may replace an MCP tool's output (updated_mcp_tool_output), no other.

So in Cursor the guard replaces MCP results, refuses file reads, wraps shell commands, and
cannot do anything about the results of Cursor's own web tools except log them.
"""

from __future__ import annotations

import json

from .. import engine, run, toolio
from ..engine import Call, Decision
from . import Agent

_TOOLS = {"Shell": "Bash", "Read": "Read", "Grep": "Grep", "Write": "Write", "Delete": "Write", "Edit": "Edit"}


def _object(value) -> dict:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    return value if isinstance(value, dict) else {}


class Cursor(Agent):
    name, title = "cursor", "Cursor"

    def read(self, d: dict) -> tuple[str, Call] | None:
        event = str(d.get("hook_event_name") or "")
        session = str(d.get("conversation_id") or "")
        roots = d.get("workspace_roots") if isinstance(d.get("workspace_roots"), list) else []
        cwd = str(d.get("cwd") or (roots[0] if roots else ""))
        ids = {"client": self.name, "native_event": event, "tool_use_id": d.get("tool_use_id")}
        if event == "beforeShellExecution":
            call = self._shell(str(d.get("command") or ""), {"command": d.get("command")}, session, cwd, ids)
            return "before", call
        if event == "beforeReadFile":  # the content is here before the model has it: judge it as a result
            call = Call("Read", {"file_path": str(d.get("file_path") or "")}, session, cwd, ids, self.title)
            call.text = call.raw = str(d.get("content") or "")
            return "after", call
        if event == "beforeMCPExecution":
            name = f"mcp__{d.get('mcp_server_name') or 'server'}__{d.get('tool_name') or ''}"
            return "before", Call(name, _object(d.get("tool_input")), session, cwd, ids, self.title)
        if event not in ("preToolUse", "postToolUse"):
            return None
        native = str(d.get("tool_name") or "")
        given = _object(d.get("tool_input"))
        tool = _TOOLS.get(native) or ("mcp__" + native[4:] if native.startswith("MCP:") else native)
        if tool == "Bash":
            call = self._shell(str(given.get("command") or ""), given, session, str(given.get("working_directory") or cwd), ids)
        else:
            tool_input = dict(given)
            path = given.get("file_path") or given.get("path") or given.get("target_file")
            if path and tool in ("Read", "Grep", "Edit", "Write"):
                tool_input["file_path" if tool != "Grep" else "path"] = path
            call = Call(tool, tool_input, session, cwd, ids, self.title)
            call.given, call.wrapped = given, False
        call.ids["native_tool"] = native
        if event == "preToolUse":
            return "rewrite", call  # no question is enforced here; only the shell command is rewritten
        if tool == "Read":
            return None  # judged before the read
        if call.wrapped:
            from .. import config, store
            if store.judged(config.load(), session, call.tool_input["command"]):
                return None  # jevguard-run has judged what the command printed
        call.raw = d.get("tool_output")
        parsed = call.raw
        if isinstance(parsed, str):
            try:
                parsed = json.loads(parsed)
            except ValueError:
                pass
        call.text, call.images = toolio.text_of("", parsed)
        return "after", call

    def _shell(self, command: str, given: dict, session: str, cwd: str, ids: dict) -> Call:
        inner = run.unwrap(command)
        call = Call("Bash", {**given, "command": engine.without_own_lines(inner if inner is not None else command)},
                    session, cwd, dict(ids), self.title)
        call.given, call.wrapped = given, inner is not None
        return call

    def answer(self, d: dict, phase: str, call: Call, decision: Decision) -> dict | None:
        event = d.get("hook_event_name")
        if decision.action == "replace":
            if event == "beforeReadFile":
                return {"permission": "deny", "user_message": "jevguard withheld this file: it scores as a prompt injection. "
                                                              "See `jevguard log`."}
            if call.tool.startswith("mcp__"):
                return {"updated_mcp_tool_output": decision.notice}
            return None  # Cursor lets a hook replace nothing else; the log has it
        message = f"jevguard: {decision.reason}"
        return {"permission": "ask", "user_message": message, "agent_message": message}

    def untouched(self, d: dict, phase: str, call: Call) -> dict | None:
        from .. import config
        if phase != "rewrite" or call.tool != "Bash" or call.wrapped or not call.tool_input.get("command"):
            return None
        if not run.wanted(call, config.load()):
            return None
        return {"permission": "allow",
                "updated_input": {**call.given, "command": run.wrap(call.tool_input["command"], self.name, call.session)}}


AGENT = Cursor()
