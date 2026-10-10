"""Codex CLI (OpenAI). From the hook schemas in its repository as read on 2026-10-10
(openai/codex, codex-rs/hooks/schema/generated). NOT VERIFIED AGAINST CODEX: its hooks page
was withheld by this guard and a probe with codex 0.160.0 did not get a hook to run, so where
the hooks are configured is not established and `jevguard install` does not do it yet.

Input and output have Claude Code's form:

    before:  {hook_event_name: "PreToolUse", session_id, cwd, tool_name, tool_input, tool_use_id, turn_id, model, ...}
             may answer hookSpecificOutput.permissionDecision allow | deny | ask, and updatedInput
    after:   the same with tool_response; may answer hookSpecificOutput.updatedMCPToolOutput

Only an MCP tool's result can be replaced. What a shell command printed cannot, so in block
mode a command whose output the guard would look at is rewritten to run through `jevguard-run`,
which scans the output before Codex gets it.
"""

from __future__ import annotations

from .. import engine, run, toolio
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
        tool = "Bash" if native in _SHELL else native
        tool_input = dict(given)
        command = given.get("command")
        if isinstance(command, list):  # an argv, as the shell tool takes it: ["bash", "-lc", "<the command>"]
            command = command[-1] if len(command) == 3 and command[1] in ("-c", "-lc") else " ".join(map(str, command))
        call = Call(tool, tool_input, str(d.get("session_id") or ""), str(d.get("cwd") or ""),
                    {"tool_use_id": d.get("tool_use_id"), "client": self.name, "native_tool": native}, self.title)
        call.given, call.wrapped = given, False
        if isinstance(command, str):
            inner = run.unwrap(command)
            call.wrapped = inner is not None
            tool_input["command"] = engine.without_own_lines(inner if inner is not None else command)
        if event == "PreToolUse":
            return "before", call
        if call.wrapped:
            from .. import config, store
            if store.judged(config.load(), call.session, tool_input["command"]):
                return None  # jevguard-run has judged what the command printed
        call.raw = d.get("tool_response")
        call.text, call.images = toolio.text_of(call.tool if call.tool.startswith("mcp__") else "", call.raw)
        return "after", call

    def _shell_input(self, call: Call, command: str) -> dict:
        given = call.given.get("command")
        if isinstance(given, list):  # keep the argv form the tool was called with
            return {**call.given, "command": [*given[:-1], command] if len(given) == 3 else ["bash", "-lc", command]}
        return {**call.given, "command": command}

    def answer(self, d: dict, phase: str, call: Call, decision: Decision) -> dict | None:
        if decision.action == "replace":
            # Codex lets a hook replace nothing after the fact (0.160.0 turns updatedMCPToolOutput
            # down as unsupported). What it does honour is stopping the turn, so the model does not
            # get to act on what it was just given. The text stays in the session: start a new one.
            why = ("jevguard: a tool result scored as a prompt injection and Codex gives a hook no way to withhold it. "
                   "The turn was stopped before the model could act on it. See `jevguard log`; continue in a new session.")
            return {"continue": False, "stopReason": why, "reason": why}
        # Codex cannot be made to ask either ("ask" is turned down as unsupported and the call
        # runs). Where the guard would ask, the call is refused, and the owner can run it himself.
        return {"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "deny",
            "permissionDecisionReason": f"jevguard: {decision.reason} Codex cannot be made to ask the owner, "
                                        "so the call was not run; the owner can run it himself."}}

    def untouched(self, d: dict, phase: str, call: Call) -> dict | None:
        from .. import config
        if phase != "before" or call.tool != "Bash" or call.wrapped or not isinstance(call.tool_input.get("command"), str):
            return None
        if not run.wanted(call, config.load()):
            return None
        wrapped = run.wrap(call.tool_input["command"], self.name, call.session)
        # a rewrite is taken only together with "allow" (and "allow" only together with a rewrite)
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow",
                                       "updatedInput": self._shell_input(call, wrapped)}}


AGENT = Codex()
