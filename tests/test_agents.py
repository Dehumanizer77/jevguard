"""One adapter per agent: each turns its agent's hook input into a call the engine understands and
the engine's decision into what that agent's hook may answer.

The Grok inputs are what grok 1.0.30 really sent (recorded 2026-10-10); tests/e2e_grok.py runs
the same against the live program. The Copilot, Cursor, Codex and Hermes inputs are built from
their documentation and schemas: those adapters have not been run against the real agents.
"""

import json

import pytest

from conftest import ATTACK, BENIGN
from jevguard import run


@pytest.fixture
def ext(guard, tmp_path):
    """A directory whose files are outside content, in block mode."""
    folder = tmp_path / "ext"
    folder.mkdir()
    guard.configure(mode="block", external_paths=[str(folder)])
    return folder


def notice_in(text) -> bool:
    return isinstance(text, str) and json.loads(text)["firewall"] == "blocked" and ATTACK not in text


# ---- Grok -----------------------------------------------------------------------------------------
def grok(event, tool, tool_input, result=None, cwd="/work"):
    d = {"hook_event_name": event, "hookEventName": "pre_tool_use" if event == "PreToolUse" else "post_tool_use",
         "sessionId": "g1", "session_id": "g1", "cwd": cwd, "workspaceRoot": cwd, "toolName": tool, "tool_name": tool,
         "toolInput": tool_input, "tool_input": tool_input, "toolUseId": "call-1", "permissionMode": "default"}
    if result is not None:
        d.update(toolResult=result, tool_response=result, toolResultTruncated=False)
    return d


def bash_result(text, command):
    return {"type": "Bash", "output": list(text.encode()), "output_for_prompt": "exit: 0\n" + text, "exit_code": 0,
            "command": command, "truncated": False, "signal": None, "timed_out": False, "description": "show it",
            "current_dir": "/work", "output_file": "/home/u/.grok/sessions/x/terminal/call-1.log",
            "total_bytes": len(text), "was_bare_echo": False}


def test_grok_shell_result_is_replaced_in_groks_own_shape(guard, ext):
    command = f"cat {ext}/note.txt"
    out = guard.raw(grok("PostToolUse", "run_terminal_command", {"command": command, "description": "show it"},
                         bash_result(ATTACK + "\n", command)), "--agent", "grok")
    new = out["hookSpecificOutput"]["updatedToolOutput"]
    assert new["type"] == "Bash" and new["command"] == command and new["exit_code"] == 0   # the shape and the call's own words stay
    assert notice_in(new["output_for_prompt"]) and bytes(new["output"]).decode() == new["output_for_prompt"]
    assert new["output_file"] == ""            # it pointed at a copy of the original output
    rec = guard.log()[-1]
    assert rec["action"] == "blocked" and rec["tool"] == "Bash" and rec["native_tool"] == "run_terminal_command" and rec["client"] == "grok"
    # the text was counted once, not once per field it stands in
    assert rec["chars"] < 2 * len(ATTACK)
    assert guard.raw(grok("PostToolUse", "run_terminal_command", {"command": command}, bash_result(BENIGN + "\n", command)),
                     "--agent", "grok") is None


@pytest.mark.parametrize("tool, tool_input, result, where", [
    ("read_file", {"target_file": "EXT/note.txt"},
     {"type": "ReadFile", "FileContent": {"content": "1→" + ATTACK, "content_concise": "1→" + ATTACK,
                                          "absolute_path": "EXT/note.txt", "offset": None, "raw_output": ATTACK, "total_lines": 1}},
     ("FileContent", "content")),
    ("grep", {"pattern": "instructions", "path": "EXT"},
     {"type": "GrepSearch", "stdout": list(("EXT/note.txt\n1:" + ATTACK).encode())}, ("stdout",)),
    ("list_dir", {"target_directory": "EXT"},
     {"type": "ListDir", "Content": {"content": "note.txt " + ATTACK, "absolute_root_path": "EXT"}}, ("Content", "content")),
    ("web_fetch", {"url": "https://news.example.com/a"},
     {"type": "WebFetch", "Content": {"url": "https://news.example.com/a", "content": ATTACK, "content_type": "text/html",
                                      "status_code": 200, "bytes": 99}}, ("Content", "content")),
])
def test_grok_other_tools_keep_their_shape_too(guard, ext, tool, tool_input, result, where):
    fill = lambda o: json.loads(json.dumps(o).replace("EXT", str(ext)))  # noqa: E731
    out = guard.raw(grok("PostToolUse", tool, fill(tool_input), fill(result)), "--agent", "grok")
    new = out["hookSpecificOutput"]["updatedToolOutput"]
    assert new["type"] == result["type"]
    value = new
    for key in where:
        value = value[key]
    assert notice_in(bytes(value).decode() if isinstance(value, list) else value)
    assert ATTACK not in json.dumps(new) and guard.log()[-1]["mode"] == "external"
    for kept in ("absolute_path", "absolute_root_path", "url", "content_type", "status_code"):
        for part in (v for v in new.values() if isinstance(v, dict)):
            if kept in part:
                assert part[kept] == fill(result)[where[0]][kept]


def test_grok_mcp_result_becomes_the_notice_and_local_output_is_left_alone(guard, ext, jev):
    out = guard.raw(grok("PostToolUse", "linear__list_issues", {"team": "x"}, [{"type": "text", "text": ATTACK}]), "--agent", "grok")
    assert notice_in(out["hookSpecificOutput"]["updatedToolOutput"]) and guard.log()[-1]["tool"] == "mcp__linear__list_issues"
    n = len(jev.requests)
    assert guard.raw(grok("PostToolUse", "run_terminal_command", {"command": "git status"}, bash_result(ATTACK, "git status")),
                     "--agent", "grok") is None and len(jev.requests) == n


def test_grok_is_asked_like_claude_and_the_rewrite_keeps_groks_fields(guard):
    out = guard.raw(grok("PreToolUse", "run_terminal_command", {"command": "jevguard gate off", "description": "switch it off"}),
                    "--agent", "grok")["hookSpecificOutput"]
    assert out["permissionDecision"] == "ask" and "jevguard gate" in out["permissionDecisionReason"]
    assert out["updatedInput"]["description"] == "switch it off"
    assert out["updatedInput"]["command"].split("\n") == [
        "# jevguard: CHANGES THE GUARD", "# jevguard: why: the command runs `jevguard gate`",
        "# jevguard: Grok says: switch it off", "jevguard gate off"]
    edit = grok("PreToolUse", "search_replace", {"file_path": str(guard.home / "config" / "config.json"), "old_string": "a"})
    assert guard.raw(edit, "--agent", "grok")["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_grok_is_recognised_when_it_runs_the_hook_from_claudes_settings(guard, ext, tmp_path):
    """Grok reads ~/.claude/settings.json and starts the same command Claude Code does, with no --agent."""
    command = f"cat {ext}/note.txt"
    payload = grok("PostToolUse", "run_terminal_command", {"command": command}, bash_result(ATTACK + "\n", command))
    home = {"HOME": str(tmp_path), "GROK_HOOK_EVENT": "post_tool_use"}
    assert guard.raw(payload, env=home)["hookSpecificOutput"]["updatedToolOutput"]["type"] == "Bash"
    # with hooks of its own for the guard, those do the work and this run stands back
    (tmp_path / ".grok" / "hooks").mkdir(parents=True)
    (tmp_path / ".grok" / "hooks" / "jevguard.json").write_text("{}")
    n = len(guard.log())
    assert guard.raw(payload, env=home) is None and len(guard.log()) == n
    assert guard.raw(payload, "--agent", "grok", env=home) is not None


# ---- Copilot CLI ----------------------------------------------------------------------------------
def test_copilot_result_is_replaced_and_a_call_is_asked_about(guard, ext):
    after = {"sessionId": "c1", "timestamp": 1, "cwd": "/work", "toolName": "bash", "toolArgs": {"command": f"cat {ext}/note.txt"},
             "toolResult": {"resultType": "success", "textResultForLlm": ATTACK}}
    out = guard.raw(after, "--agent", "copilot")
    assert out["modifiedResult"]["resultType"] == "success" and notice_in(out["modifiedResult"]["textResultForLlm"])
    assert guard.log()[-1]["client"] == "copilot" and guard.log()[-1]["native_tool"] == "bash"
    fetch = dict(after, toolName="web_fetch", toolArgs=json.dumps({"url": "https://news.example.com/a"}))  # arguments as a string
    assert notice_in(guard.raw(fetch, "--agent", "copilot")["modifiedResult"]["textResultForLlm"])
    unknown = dict(after, toolName="github-mcp-server-list_issues", toolArgs={})  # a tool it does not know: from outside
    assert guard.raw(unknown, "--agent", "copilot") is not None and guard.log()[-1]["mode"] == "external"
    assert guard.raw(dict(after, toolName="bash", toolArgs={"command": "git status"}), "--agent", "copilot") is None
    before = {"sessionId": "c1", "timestamp": 1, "cwd": "/work", "toolName": "bash", "toolArgs": {"command": "jevguard gate off"}}
    out = guard.raw(before, "--agent", "copilot")
    assert out["permissionDecision"] == "ask" and out["modifiedArgs"]["command"].startswith("# jevguard: CHANGES THE GUARD\n")


# ---- Codex CLI ------------------------------------------------------------------------------------
def codex(event, tool, tool_input, response=None):
    """Input as codex 0.160.0 really sends it (recorded 2026-10-10): the shell is "Bash" and its
    result the plain text it printed."""
    d = {"hook_event_name": event, "session_id": "x1", "cwd": "/work", "tool_name": tool, "tool_input": tool_input,
         "tool_use_id": "t1", "turn_id": "u1", "model": "gpt", "permission_mode": "default", "transcript_path": "/t"}
    if response is not None:
        d["tool_response"] = response
    return d


def test_codex_result_is_replaced_by_way_of_the_hooks_feedback(guard, ext):
    """Codex has no field for a replacement, but puts a blocking hook's feedback in place of the
    tool result. The notice goes out as that feedback."""
    command = f"cat {ext}/note.txt"
    out = guard.raw(codex("PostToolUse", "Bash", {"command": command}, ATTACK + "\n"), "--agent", "codex")
    assert out["decision"] == "block" and notice_in(out["reason"]) and set(out) == {"decision", "reason"}
    rec = guard.log()[-1]
    assert rec["action"] == "blocked" and rec["client"] == "codex" and rec["native_tool"] == "Bash"
    assert guard.raw(codex("PostToolUse", "Bash", {"command": command}, BENIGN + "\n"), "--agent", "codex") is None
    mail = guard.raw(codex("PostToolUse", "mcp__mail__read", {}, [{"type": "text", "text": ATTACK + " mail"}]), "--agent", "codex")
    assert mail["decision"] == "block" and notice_in(mail["reason"])
    assert guard.raw(codex("PostToolUse", "Bash", {"command": "git status"}, ATTACK), "--agent", "codex") is None   # local


def test_codex_commands_are_left_as_they_are(guard, ext):
    """No wrapper here: the hook after the call does the work, outside Codex's sandbox."""
    for command in (f"cat {ext}/note.txt", "curl -s https://news.example.com/a", "git status"):
        assert guard.raw(codex("PreToolUse", "Bash", {"command": command}), "--agent", "codex") is None


def test_codex_cannot_ask_so_the_call_is_refused_with_the_reason(guard, ext):
    out = guard.raw(codex("PreToolUse", "Bash", {"command": "jevguard gate off"}), "--agent", "codex")["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny" and "jevguard gate" in out["permissionDecisionReason"]
    assert "updatedInput" not in out
    patch = codex("PreToolUse", "apply_patch", {"command": "*** Begin Patch", "file_path": str(guard.home / "config" / "config.json")})
    assert guard.raw(patch, "--agent", "codex")["hookSpecificOutput"]["permissionDecision"] == "deny"


# ---- Cursor ---------------------------------------------------------------------------------------
def cursor(event, **fields):
    return {"hook_event_name": event, "conversation_id": "k1", "generation_id": "g", "workspace_roots": ["/work"], **fields}


def test_cursor_shell_is_wrapped_before_it_runs_and_the_gate_asks_at_the_shell_event(guard, ext):
    command = f"cat {ext}/note.txt"
    out = guard.raw(cursor("preToolUse", tool_name="Shell", tool_input={"command": command, "working_directory": "/work"}),
                    "--agent", "cursor")
    assert out["permission"] == "allow" and run.unwrap(out["updated_input"]["command"]) == command
    assert out["updated_input"]["working_directory"] == "/work"
    assert guard.raw(cursor("preToolUse", tool_name="Shell", tool_input={"command": "git status"}), "--agent", "cursor") is None
    # no question is enforced at preToolUse, so none is put there; it is put where Cursor does enforce it
    assert guard.raw(cursor("preToolUse", tool_name="Shell", tool_input={"command": "jevguard gate off"}), "--agent", "cursor") is None
    for command in ("jevguard gate off", run.wrap("jevguard gate off", "cursor", "k1")):
        asked = guard.raw(cursor("beforeShellExecution", command=command, cwd="/work"), "--agent", "cursor")
        assert asked["permission"] == "ask" and "jevguard gate" in asked["user_message"] and asked["agent_message"]
    assert guard.raw(cursor("beforeShellExecution", command="git status", cwd="/work"), "--agent", "cursor") is None


def test_cursor_file_is_refused_before_the_read_and_mcp_output_replaced(guard, ext):
    read = cursor("beforeReadFile", file_path=f"{ext}/note.txt", content=ATTACK)
    assert guard.raw(read, "--agent", "cursor")["permission"] == "deny" and guard.log()[-1]["action"] == "blocked"
    assert guard.raw(cursor("beforeReadFile", file_path=f"{ext}/ok.txt", content=BENIGN), "--agent", "cursor") is None
    assert guard.raw(cursor("beforeReadFile", file_path="/work/a.py", content=ATTACK), "--agent", "cursor") is None  # local
    mcp = cursor("postToolUse", tool_name="MCP:read_mail", tool_input={}, tool_output=json.dumps([{"type": "text", "text": ATTACK}]))
    assert notice_in(guard.raw(mcp, "--agent", "cursor")["updated_mcp_tool_output"])
    # a wrapped shell command was judged by the wrapper; one that was not is logged, which is all Cursor allows
    shell = cursor("postToolUse", tool_name="Shell", tool_input={"command": f"cat {ext}/note.txt"}, tool_output=json.dumps({"output": ATTACK + " x"}))
    assert guard.raw(shell, "--agent", "cursor") is None and guard.log()[-1]["action"] == "blocked"
    from jevguard import config, store
    import os
    os.environ["JEVGUARD_HOME"] = str(guard.home)
    try:
        store.judged(config.load(), "k1", "cat x", mark=True)   # as jevguard-run leaves it
    finally:
        del os.environ["JEVGUARD_HOME"]
    n = len(guard.log())
    done = cursor("postToolUse", tool_name="Shell", tool_input={"command": run.wrap("cat x", "cursor", "k1")}, tool_output="{}")
    assert guard.raw(done, "--agent", "cursor") is None and len(guard.log()) == n


# ---- installing into each agent's own settings ----------------------------------------------------
def test_install_writes_each_agents_own_file_and_uninstall_takes_it_out(guard, monkeypatch, tmp_path, capsys):
    from jevguard import cli
    monkeypatch.setenv("JEVGUARD_HOME", str(guard.home))
    monkeypatch.setenv("HOME", str(tmp_path))
    hook = str(cli.HOOK)
    # the owner's own hooks in the two files that are shared
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "hooks.json").write_text(json.dumps({"version": 1, "hooks": {"stop": [{"command": "./mine.sh"}]}}))
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "hooks.json").write_text(json.dumps({"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "mine"}]}]}}))
    for agent in ("grok", "copilot", "cursor", "codex", "hermes"):
        assert cli.main(["install", "--agent", agent]) == 0
        assert cli.main(["install", "--agent", agent]) == 0   # a second time changes nothing
    said = capsys.readouterr().out
    assert said.count("no change") == 4 and "review the new hooks" in said and "hermes plugins enable" in said
    grok_hooks = json.loads((tmp_path / ".grok" / "hooks" / "jevguard.json").read_text())["hooks"]
    assert grok_hooks["PostToolUse"][0]["hooks"][0]["command"] == f"{hook} --agent grok" and "matcher" not in grok_hooks["PreToolUse"][0]
    copilot = json.loads((tmp_path / ".copilot" / "hooks" / "jevguard.json").read_text())
    assert copilot["version"] == 1 and copilot["hooks"]["preToolUse"][0]["bash"] == f"{hook} --agent copilot"
    cursor_hooks = json.loads((tmp_path / ".cursor" / "hooks.json").read_text())["hooks"]
    assert cursor_hooks["stop"] == [{"command": "./mine.sh"}] and cursor_hooks["beforeReadFile"][0]["command"] == f"{hook} --agent cursor"
    codex_hooks = json.loads((tmp_path / ".codex" / "hooks.json").read_text())["hooks"]
    assert [g["hooks"][0]["command"] for g in codex_hooks["PreToolUse"]] == ["mine", f"{hook} --agent codex"]
    assert (tmp_path / ".hermes" / "plugins" / "jevguard" / "plugin.yaml").exists()
    assert (tmp_path / ".hermes" / "plugins" / "jevguard" / "root").read_text().strip() == str(cli.Path(hook).parent.parent)
    assert cli.main(["status"]) == 0
    assert "installed for other agents: grok, copilot, cursor, codex, hermes" in capsys.readouterr().out
    for agent in ("grok", "copilot", "cursor", "codex", "hermes"):
        assert cli.main(["uninstall", "--agent", agent]) == 0
    capsys.readouterr()
    assert cli.main(["status"]) == 0
    assert "installed for other agents: none" in capsys.readouterr().out   # the owner's own hooks do not count
    assert not (tmp_path / ".grok" / "hooks" / "jevguard.json").exists() and not (tmp_path / ".hermes" / "plugins" / "jevguard").exists()
    assert json.loads((tmp_path / ".cursor" / "hooks.json").read_text())["hooks"] == {"stop": [{"command": "./mine.sh"}]}
    assert json.loads((tmp_path / ".codex" / "hooks.json").read_text())["hooks"]["PreToolUse"] == [{"hooks": [{"type": "command", "command": "mine"}]}]


@pytest.mark.parametrize("path", ["~/.grok/hooks/jevguard.json", "~/.copilot/hooks/jevguard.json", "~/.cursor/hooks.json",
                                  "~/.codex/hooks.json", "~/.hermes/plugins/jevguard/__init__.py"])
def test_the_other_agents_hook_files_are_guarded_like_claudes_settings(guard, path):
    for payload in ({"command": f"rm -f {path}"}, {"command": f"echo '{{}}' > {path}"}):
        out = guard.hook("PreToolUse", "Bash", payload)
        assert out and out["hookSpecificOutput"]["permissionDecision"] == "ask", payload
    assert guard.hook("PreToolUse", "Write", {"file_path": path, "content": "{}"})["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert guard.hook("PreToolUse", "Bash", {"command": f"cat {path}"}) is None   # looking is not a change


def test_an_agents_own_file_tools_do_not_read_the_guards_keys_unasked(guard, tmp_path, monkeypatch):
    """Claude Code is kept out of the guard's directories by two permission rules. No other agent
    has those: there the check before the call is all that stands in front of the API key."""
    key = str(guard.home / "config" / "typesafe.key")
    out = guard.raw(grok("PreToolUse", "read_file", {"target_file": key}), "--agent", "grok")["hookSpecificOutput"]
    assert out["permissionDecision"] == "ask" and "API key" in out["permissionDecisionReason"]
    # a search in the directory, and one from above it
    for where in (str(guard.home / "state"), str(guard.home), str(tmp_path)):
        out = guard.raw(grok("PreToolUse", "grep", {"pattern": "apikey", "path": where}), "--agent", "grok")
        assert out["hookSpecificOutput"]["permissionDecision"] == "ask", where
    listing = grok("PreToolUse", "list_dir", {"target_directory": str(guard.home / "config")})
    assert guard.raw(listing, "--agent", "grok")["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert guard.log()[-1]["action"] == "asked" and guard.log()[-1]["taint"] == "guard"
    # anything else is read as before
    (tmp_path / "project").mkdir()
    assert guard.raw(grok("PreToolUse", "read_file", {"target_file": str(tmp_path / "project" / "notes.txt")}), "--agent", "grok") is None
    assert guard.raw(grok("PreToolUse", "grep", {"pattern": "x", "path": str(tmp_path / "project")}), "--agent", "grok") is None
    # the other agents
    view = {"sessionId": "c1", "timestamp": 1, "cwd": "/work", "toolName": "view", "toolArgs": {"path": key}}
    assert guard.raw(view, "--agent", "copilot")["permissionDecision"] == "ask"
    out = guard.raw(cursor("beforeReadFile", file_path=key, content="apikey_0000"), "--agent", "cursor")
    assert out["permission"] == "deny" and "API key" in out["user_message"]   # this event cannot ask
    assert guard.raw(cursor("beforeReadFile", file_path=str(tmp_path / "project" / "notes.txt"), content=BENIGN), "--agent", "cursor") is None
    assert guard.raw(codex("PreToolUse", "Bash", {"command": f"cat {key}"}), "--agent", "codex")["hookSpecificOutput"]["permissionDecision"] == "deny"
    from jevguard.agents import hermes
    monkeypatch.setenv("JEVGUARD_HOME", str(guard.home))
    ran = []
    refused = hermes.around("read_file", {"path": key}, lambda args: ran.append(args) or "apikey_0000", {"session_id": "h1"})
    assert "did not run this call" in refused and "API key" in refused and not ran
    # with protect_guard off the owner has said he does not want these questions
    guard.configure(protect_guard=False)
    assert guard.raw(grok("PreToolUse", "read_file", {"target_file": key}), "--agent", "grok") is None


# ---- Hermes ---------------------------------------------------------------------------------------
def test_hermes_middleware_replaces_refuses_and_passes(guard, ext, monkeypatch):
    from jevguard.agents import hermes
    monkeypatch.setenv("JEVGUARD_HOME", str(guard.home))
    ran = []

    def tool(result):
        return lambda args: ran.append(args) or result

    ids = {"session_id": "h1", "tool_call_id": "c1"}
    out = hermes.around("terminal", {"command": f"cat {ext}/note.txt"}, tool(json.dumps({"output": ATTACK, "exit_code": 0})), ids)
    assert notice_in(out) and guard.log()[-1]["client"] == "hermes" and guard.log()[-1]["native_tool"] == "terminal"
    assert hermes.around("terminal", {"command": "git status"}, tool("on branch main"), ids) == "on branch main"
    assert notice_in(hermes.around("web_extract", {"urls": ["https://news.example.com/a"]}, tool(ATTACK + " page"), ids))
    assert notice_in(hermes.around("mcp_mail_read", {}, tool(ATTACK + " mail"), ids))
    assert hermes.around("memory", {"action": "add"}, tool(ATTACK), ids) == ATTACK   # the agent's own state: not scanned
    # where the guard would ask, the call is not run at all
    before = len(ran)
    refused = hermes.around("terminal", {"command": "jevguard gate off"}, tool("gate: off"), ids)
    assert "did not run this call" in refused and "jevguard gate" in refused and len(ran) == before


def test_hermes_plugin_is_a_doorway_to_the_same_code(guard, ext, monkeypatch, tmp_path):
    import importlib.util
    from conftest import ROOT
    monkeypatch.setenv("JEVGUARD_HOME", str(guard.home))
    monkeypatch.setenv("JEVGUARD_ROOT", str(ROOT))
    spec = importlib.util.spec_from_file_location("hermes_plugin", ROOT / "integrations" / "hermes" / "jevguard" / "__init__.py")
    plugin = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(plugin)
    registered = {}
    plugin.register(type("Ctx", (), {"register_middleware": lambda self, name, cb: registered.update({name: cb})})())
    out = registered["tool_execution"](tool_name="terminal", args={"command": f"cat {ext}/note.txt"},
                                       next_call=lambda args: ATTACK, session_id="h2", tool_call_id="c2")
    assert notice_in(out)
