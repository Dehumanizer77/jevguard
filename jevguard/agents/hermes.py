"""Hermes Agent. From the integration notes of jooray/hermes-firewall (docs/hermes-integration.md,
written against hermes-agent 866cd752b5), whose detector this guard is built on.
NOT RUN AGAINST HERMES: it is not installed where this was written.

Hermes has no hook commands. A plugin in ~/.hermes/plugins/<name>/ registers a `tool_execution`
middleware that wraps every tool call in the agent's own process: it is given the tool's name
and arguments and a `next_call` that runs the tool, and whatever it returns is what the model
gets. So this adapter is called from the plugin in integrations/hermes, not from the hook.

Hermes cannot be asked to put a question to the owner from there. Where the guard would ask
(a change to itself, a risky call after outside content), the call is refused with the reason,
and the owner can run it himself.

    terminal {command, workdir}      read_file, search_files {path}      write_file, patch {path}
    web_search, web_extract, browser_*, vision_analyze ...: content from outside
    mcp_<server>_<tool>: an MCP tool
"""

from __future__ import annotations

import json
import os

from .. import config, engine, toolio
from ..engine import Call

TITLE = "Hermes"
_OUTSIDE = {"web_search", "web_extract", "x_search", "vision_analyze", "video_analyze", "computer_use", "feishu_doc_read"}
_PASS_ON = {"_ToolTimeoutResult", "_ToolCancelledResult"}  # not results: Hermes' own markers


def to_call(tool_name: str, args: dict, ids: dict) -> Call:
    tool_input = dict(args)
    if tool_name == "terminal":
        tool = "Bash"
    elif tool_name == "execute_code":  # a program, judged like a command by the addresses in it
        tool, tool_input = "Bash", {**args, "command": str(args.get("code") or args.get("command") or "")}
    elif tool_name in ("read_file", "search_files", "write_file", "patch"):
        tool = {"read_file": "Read", "search_files": "Grep", "write_file": "Write", "patch": "Edit"}[tool_name]
        path = args.get("path") or args.get("file_path")
        if path:
            tool_input["path" if tool == "Grep" else "file_path"] = path
    elif tool_name in _OUTSIDE or (tool_name.startswith("browser_") and "vault" not in tool_name):
        tool = f"mcp__hermes__{tool_name}"
    elif tool_name.startswith("mcp_"):
        tool = "mcp__" + tool_name[4:]
    else:
        tool = tool_name
    if isinstance(tool_input.get("command"), str):
        tool_input["command"] = engine.without_own_lines(tool_input["command"])
    return Call(tool, tool_input, str(ids.get("session_id") or ""), str(args.get("workdir") or ""),
                {"tool_use_id": ids.get("tool_call_id"), "client": "hermes", "native_tool": tool_name}, TITLE)


def text_of(result) -> tuple[str, list]:
    parsed = result
    if isinstance(result, str):
        try:
            parsed = json.loads(result)
        except ValueError:
            return result, []
    return toolio.text_of("", parsed)


_PROCESS = {"process", "process_manage"}  # poll, log or wait for a command that runs in the background


def _background(call: Call, tool_name: str, args: dict, result) -> None:
    """A command started in the background returns a session_id and no output; the process tool
    returns the output later, with the command that printed it. As the plugin this adapter is
    derived from has it: the output of a background job is the output of what started it."""
    parsed = result
    if isinstance(result, str):
        try:
            parsed = json.loads(result)
        except ValueError:
            parsed = None
    parsed = parsed if isinstance(parsed, dict) else {}
    if tool_name in ("terminal", "execute_code") and parsed.get("session_id"):
        call.later_ids = [str(parsed["session_id"])]
    elif tool_name in _PROCESS:
        command = parsed.get("command") if isinstance(parsed.get("command"), str) else ""
        call.tool, call.tool_input = "Bash", {"command": engine.without_own_lines(command)}
        call.task_ids = [str(args["session_id"])] if args.get("session_id") else []


def around(tool_name: str, args, next_call, ids: dict):
    """The middleware: the gate, then the tool, then its result."""
    given = args if isinstance(args, dict) else {}
    call, cfg = to_call(str(tool_name or ""), given, ids), None
    try:
        cfg = config.load()
        # Hermes puts results too large to hand over into files under its cache, and the model
        # reads them back from there. What is in them is tool output, whichever tool it was; as
        # in the plugin this is derived from, all of it counts as content from outside.
        cfg.external_paths = [*cfg.external_paths, os.path.join(os.environ.get("HERMES_HOME") or "~/.hermes", "cache", "spillover")]
        decision = engine.before(call, cfg)
    except Exception as exc:
        decision = engine.after_error("before", call, cfg, {}, exc)
    if decision is not None:
        return ("jevguard did not run this call: it would have asked the owner first, and cannot from inside Hermes. "
                f"{decision.reason} The owner can run it himself.")
    result = next_call(args)
    if type(result).__name__ in _PASS_ON:
        return result
    ctx: dict = {}
    try:
        call.raw = result if isinstance(result, (str, dict, list)) else str(result)
        call.text, call.images = text_of(result)
        _background(call, str(tool_name or ""), given, result)
        decision = engine.after(call, cfg, ctx)
    except Exception as exc:  # a guard bug must not take the agent down
        decision = engine.after_error("after", call, cfg, ctx, exc)
    return decision.notice if decision is not None and decision.action == "replace" else result
