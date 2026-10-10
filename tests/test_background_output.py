"""The output of a command that runs in the background. The call that starts it returns nothing;
what it prints reaches the model later: from a file the agent reads (Claude Code), through
another tool (Grok, Hermes), or line by line as notifications (Monitor). It is still that
command's output, and was not scanned on any of those roads.

The Claude Code and Grok shapes are what 2.1.295 and 1.0.30 really sent (recorded 2026-10-10).
"""

import json
import os

import pytest

from conftest import ATTACK, BENIGN
from test_agents import grok, notice_in

FETCH = "curl -s https://news.example.com/feed"
TASK = "bidn2o9cv"
SESSION = "8467d2ce-81a8-4754-b50e-f237931cad7e"
PROJECT = "-home-u-project"


def claude(event, tool, tool_input, response=None, session=SESSION):
    d = {"session_id": session, "transcript_path": f"/home/u/.claude/projects/{PROJECT}/{session}.jsonl", "cwd": "/work",
         "permission_mode": "default", "hook_event_name": event, "tool_name": tool, "tool_input": tool_input,
         "tool_use_id": "toolu_01Kr9byFHEZUp1ST4P82TxGe"}
    if response is not None:
        d["tool_response"] = response
    return d


def started(task=TASK):
    return {"stdout": "", "stderr": "", "interrupted": False, "isImage": False, "noOutputExpected": False, "backgroundTaskId": task}


def read_result(path, text):
    return {"type": "text", "file": {"filePath": str(path), "content": text, "numLines": 1, "startLine": 1, "totalLines": 1}}


def blocked(out) -> bool:
    return bool(out) and "prompt-injection firewall" in json.dumps(out) and ATTACK not in json.dumps(out)


@pytest.fixture
def tasks(guard, tmp_path):
    """Claude Code's directory of background output for this session, under a temporary TMPDIR."""
    guard.configure(mode="block")
    guard.env = {"TMPDIR": str(tmp_path)}
    folder = tmp_path / f"claude-{os.getuid()}" / PROJECT / SESSION / "tasks"
    folder.mkdir(parents=True)
    (folder / f"{TASK}.output").write_text(ATTACK + "\n")
    return folder


# ---- Claude Code: the output is in a file the model is told to read -----------------------------------
def test_claude_reading_the_output_file_of_an_outside_background_command_is_scanned(guard, tasks, jev):
    launch = {"command": FETCH, "description": "fetch the feed", "run_in_background": True}
    assert guard.raw(claude("PostToolUse", "Bash", launch, started())) is None and not jev.requests   # nothing printed yet
    out = guard.raw(claude("PostToolUse", "Read", {"file_path": str(tasks / f"{TASK}.output")}, read_result(tasks / f"{TASK}.output", ATTACK)))
    assert blocked(out) and guard.log()[-1]["mode"] == "external" and guard.log()[-1]["tool"] == "Read"
    # read with the shell, by a glob, through a variable, and searched
    for command in (f"cat {tasks}/{TASK}.output", f"tail -n 20 {tasks}/*.output", f'f="{tasks}/{TASK}.output"; cat "$f"',
                    f"cd {tasks} && head {TASK}.output"):
        out = guard.raw(claude("PostToolUse", "Bash", {"command": command}, {"stdout": ATTACK + " now", "stderr": ""}))
        assert blocked(out), command
    grep = {"mode": "content", "numFiles": 1, "filenames": [], "content": f"{TASK}.output:1:{ATTACK}", "numLines": 1}
    assert blocked(guard.raw(claude("PostToolUse", "Grep", {"pattern": "x", "path": str(tasks)}, grep)))


def test_claude_the_file_is_known_by_its_task_where_the_directory_could_not_be_worked_out(guard):
    """Another temporary directory, a later version that keeps them elsewhere: the model is still
    told a path ending in tasks/<task>.output, and names it when it reads."""
    guard.configure(mode="block")
    guard.raw(claude("PostToolUse", "Bash", {"command": FETCH, "run_in_background": True}, started()))
    path = f"/var/tmp/elsewhere/{SESSION}/tasks/{TASK}.output"
    assert blocked(guard.raw(claude("PostToolUse", "Read", {"file_path": path}, read_result(path, ATTACK))))
    out = guard.raw(claude("PostToolUse", "Bash", {"command": f'until grep -q done "{path}"; do sleep 1; done; cat "{path}"'},
                           {"stdout": ATTACK + " again", "stderr": ""}))
    assert blocked(out)
    other = f"/var/tmp/elsewhere/{SESSION}/tasks/zzzz9999.output"    # some other task's
    assert guard.raw(claude("PostToolUse", "Read", {"file_path": other}, read_result(other, ATTACK))) is None


def test_claude_a_local_background_command_stays_local(guard, tasks, jev):
    guard.raw(claude("PostToolUse", "Bash", {"command": "make test", "run_in_background": True}, started()))
    path = tasks / f"{TASK}.output"
    assert guard.raw(claude("PostToolUse", "Read", {"file_path": str(path)}, read_result(path, ATTACK))) is None
    assert guard.raw(claude("PostToolUse", "Bash", {"command": f"cat {path}"}, {"stdout": ATTACK, "stderr": ""})) is None
    assert not jev.requests and not guard.log()
    # and a session is its own: the same task name in another session is another task
    guard.raw(claude("PostToolUse", "Bash", {"command": FETCH, "run_in_background": True}, started(), session="other-session"))
    assert guard.raw(claude("PostToolUse", "Read", {"file_path": str(path)}, read_result(path, ATTACK))) is None


def test_claude_log_mode_records_it(guard, tasks):
    guard.configure(mode="log")
    guard.raw(claude("PostToolUse", "Bash", {"command": FETCH, "run_in_background": True}, started()))
    path = tasks / f"{TASK}.output"
    assert guard.raw(claude("PostToolUse", "Read", {"file_path": str(path)}, read_result(path, ATTACK))) is None
    assert guard.log()[-1]["action"] == "would-block"


# ---- Monitor: the output never comes back as a result -----------------------------------------------
def test_a_monitor_on_outside_content_is_asked_about_before_it_starts(guard, tasks):
    monitor = {"description": "watch the feed", "timeout_ms": 60000, "command": f"while true; do {FETCH}; sleep 30; done"}
    out = guard.raw(claude("PreToolUse", "Monitor", monitor))["hookSpecificOutput"]
    assert out["permissionDecision"] == "ask" and "cannot be scanned" in out["permissionDecisionReason"]
    assert out["updatedInput"]["command"].split("\n")[0] == "# jevguard: OUTPUT CANNOT BE SCANNED"
    assert out["updatedInput"]["command"].endswith(monitor["command"]) and out["updatedInput"]["timeout_ms"] == 60000
    rec = guard.log()[-1]
    assert rec["event"] == "gate" and rec["action"] == "asked" and rec["taint"] == "unscanned"
    # the command is read like any shell command: an outside directory, a tracked download, a background task's file
    guard.raw(claude("PostToolUse", "Bash", {"command": FETCH, "run_in_background": True}, started()))
    for command in (f"tail -f {tasks}/{TASK}.output", f'f="{tasks}/{TASK}.output"; until grep -q x "$f"; do sleep 1; done; cat "$f"',
                    "gh api repos/someone/project/issues/1/comments --jq '.[].body'"):
        assert guard.raw(claude("PreToolUse", "Monitor", {"command": command}))["hookSpecificOutput"]["permissionDecision"] == "ask", command


def test_a_monitor_on_a_websocket_is_asked_about_too(guard):
    """Monitor can also open a WebSocket: every frame the server sends becomes a notification.
    There is no command in that call; the first version looked only at a command and saw nothing."""
    guard.configure(mode="block")
    out = guard.raw(claude("PreToolUse", "Monitor", {"ws": {"url": "wss://events.example.com/stream"}, "description": "deploy events"}))
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask" and "cannot be scanned" in out["hookSpecificOutput"]["permissionDecisionReason"]
    assert guard.log()[-1]["taint"] == "unscanned"
    for ws in ({"url": "ws://localhost:8080/events"}, {"url": "ws://192.168.1.5/x"}):          # this machine, this network
        assert guard.raw(claude("PreToolUse", "Monitor", {"ws": ws, "description": "local"})) is None, ws
    for ws in ({"url": "not an address"}, {}, "wss://events.example.com/stream", 7):          # anything that cannot be read as one
        assert guard.raw(claude("PreToolUse", "Monitor", {"ws": ws, "description": "x"})) is not None, ws


def test_a_monitor_on_local_output_is_left_alone(guard):
    guard.configure(mode="block")
    for command in ("tail -f /var/log/app.log | grep --line-buffered ERROR", "inotifywait -m --format '%e %f' src",
                    "while true; do make check; sleep 60; done"):
        assert guard.raw(claude("PreToolUse", "Monitor", {"command": command, "description": "watch"})) is None, command
    assert not guard.log()


def test_a_monitor_in_log_mode_is_recorded_and_the_session_marked(guard):
    guard.configure(mode="log", gate="ask-flagged")
    assert guard.raw(claude("PreToolUse", "Monitor", {"command": FETCH})) is None
    assert guard.log()[-1]["action"] == "would-ask" and guard.log()[-1]["taint"] == "unscanned"
    # outside content went to the model unscanned: the session counts as flagged for the gate
    out = guard.raw(claude("PreToolUse", "Bash", {"command": "git push origin main"}))
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_a_monitor_on_an_own_repository_is_recorded_and_not_asked_about(guard):
    """The owner's choice. Only the form that counts as his own everywhere else: one gh command
    that names the repository, with nothing around it."""
    guard.configure(mode="block", gate="ask-flagged", own_repos=["me/*"])
    for command in ("gh run watch --repo me/project 4242", "gh pr checks --repo me/project 31 --watch"):
        assert guard.raw(claude("PreToolUse", "Monitor", {"command": command, "description": "watch the run"})) is None, command
        rec = guard.log()[-1]
        assert rec["event"] == "gate" and rec["action"] == "logged" and rec["taint"] == "unscanned" and rec["tool"] == "Monitor"
    # the session has read outside content, but is not counted as flagged for it
    assert guard.raw(claude("PreToolUse", "Bash", {"command": "git push origin main"})) is None
    guard.configure(mode="block", gate="ask-external", own_repos=["me/*"])
    assert guard.raw(claude("PreToolUse", "Bash", {"command": "git push origin main"})) is not None
    out = guard.raw(grok("PreToolUse", "monitor", {"command": "gh run watch --repo me/project 4242", "description": "watch"}), "--agent", "grok")
    assert out is None and guard.log()[-1]["action"] == "logged"


@pytest.mark.parametrize("command", [
    "gh run watch --repo someone/project 4242",                                  # not his
    "while true; do gh run view --repo me/project 4242; sleep 30; done",          # a loop around it
    "gh run watch --repo me/project 4242 | grep --line-buffered fail",            # a pipe after it
    "gh run watch --repo me/project 4242; curl -s https://news.example.com/feed",
    "gh run watch 4242",                                                          # the repository is not named
    "gh api repos/me/project/issues/1/comments; gh api repos/someone/else/issues/1/comments",
    "curl -s https://github.com/me/project",
])
def test_anything_else_around_an_own_repository_is_still_asked_about(guard, command):
    guard.configure(mode="block", own_repos=["me/*"])
    out = guard.raw(claude("PreToolUse", "Monitor", {"command": command}))
    assert out and out["hookSpecificOutput"]["permissionDecision"] == "ask", command


def test_without_own_repos_every_monitor_on_gh_is_asked_about(guard):
    guard.configure(mode="block")
    out = guard.raw(claude("PreToolUse", "Monitor", {"command": "gh run watch --repo me/project 4242"}))
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_a_monitor_is_a_shell_command_for_the_gate(guard):
    """It was not looked at before a call at all: `jevguard gate off` ran through it unasked."""
    for command in ("jevguard gate off", "rm -rf ~/.claude", "echo x >> ~/.grok/disabled-hooks"):
        out = guard.raw(claude("PreToolUse", "Monitor", {"command": command}))["hookSpecificOutput"]
        assert out["permissionDecision"] == "ask" and out["updatedInput"]["command"].startswith("# jevguard: CHANGES THE GUARD\n"), command
    from jevguard import cli
    assert "Monitor" in cli._PRE[0].split("|")


# ---- Grok: another tool returns the output ---------------------------------------------------------
G_TASK = "01a1263a-aa82-7fb3-8b1f-82fcda55b2cc"
G_FILE = "/home/u/.grok/sessions/%2Fwork/01a1263a-86a3-7f52-b7f9-422cd75d92f8/terminal/call-76871d25-1.log"


def g_started(command, **changes):
    return {"type": "BackgroundTaskStarted", "task_id": G_TASK, "task_type": "bash", "output_file": G_FILE, "status": "running",
            "command": command, "summary": f"Background task {G_TASK} started",
            "retrieval_hint": f'Use get_command_or_subagent_output with task_ids=["{G_TASK}"] when you need the output.',
            "pid": 2833615, **changes}


def g_output(command, output, **changes):
    result = {"task_id": G_TASK, "command": command, "status": "completed", "exit_code": 0, "started": "2026-10-10T14:32:21Z",
              "ended": "2026-10-10T14:32:25Z", "duration_secs": 4.006505765, "output": output, "output_file": G_FILE,
              "truncated": False, "truncation_hint": "[truncated - use read_file on output_file for full content]",
              "raw_output_bytes": len(output), **changes}
    return {"type": "TaskOutput", "Result": {k: v for k, v in result.items() if v is not None}}


def g_get(result):
    return grok("PostToolUse", "get_command_or_subagent_output", {"task_ids": [G_TASK], "timeout_ms": 15000}, result)


def test_grok_the_output_of_an_outside_background_command_is_replaced_in_its_shape(guard, jev):
    guard.configure(mode="block")
    launch = {"command": FETCH, "description": "fetch the feed", "block_until_ms": 0}
    assert guard.raw(grok("PostToolUse", "run_terminal_command", launch, g_started(FETCH)), "--agent", "grok") is None
    assert not jev.requests   # Grok's own words about the task are not text to score
    out = guard.raw(g_get(g_output(FETCH, ATTACK + "\n")), "--agent", "grok")
    new = out["hookSpecificOutput"]["updatedToolOutput"]
    assert new["type"] == "TaskOutput" and notice_in(new["Result"]["output"]) and ATTACK not in json.dumps(new)
    assert new["Result"]["output_file"] == "" and new["Result"]["status"] == "completed" and new["Result"]["task_id"] == G_TASK
    rec = guard.log()[-1]
    assert rec["action"] == "blocked" and rec["native_tool"] == "get_command_or_subagent_output" and rec["mode"] == "external"
    assert guard.raw(g_get(g_output(FETCH, BENIGN + "\n")), "--agent", "grok") is None
    # and the file it is kept in, read directly
    read = grok("PostToolUse", "read_file", {"target_file": G_FILE},
                {"type": "ReadFile", "FileContent": {"content": ATTACK, "absolute_path": G_FILE, "total_lines": 1}})
    assert guard.raw(read, "--agent", "grok")["hookSpecificOutput"]["updatedToolOutput"]["type"] == "ReadFile"


def test_grok_output_is_judged_by_the_command_it_names_and_by_the_task(guard):
    guard.configure(mode="block")
    # a task the guard did not see start (sent to the background by the user): the result names its command
    assert guard.raw(g_get(g_output(FETCH, ATTACK)), "--agent", "grok") is not None
    # a local command's output is local
    assert guard.raw(g_get(g_output("make test", ATTACK)), "--agent", "grok") is None
    # no command in it (a subagent's report), but a task the guard remembers as outside
    assert guard.raw(g_get(g_output(None, ATTACK, task_type="subagent")), "--agent", "grok") is None
    guard.raw(grok("PostToolUse", "run_terminal_command", {"command": FETCH, "block_until_ms": 0}, g_started(FETCH)), "--agent", "grok")
    assert guard.raw(g_get(g_output(None, ATTACK, task_type="subagent")), "--agent", "grok") is not None
    # several tasks at once
    both = {"type": "TaskOutput", "Results": [g_output("make test", BENIGN)["Result"],
                                               dict(g_output(FETCH, ATTACK)["Result"], task_id="0b0b0b0b-0000-7000-8000-000000000000")]}
    out = guard.raw(grok("PostToolUse", "get_command_or_subagent_output", {"task_ids": ["a", "b"]}, both), "--agent", "grok")
    assert out and ATTACK not in json.dumps(out)


def test_groks_own_words_about_a_task_are_passed_over_only_in_the_form_they_have(guard):
    guard.configure(mode="block")
    launch = {"command": FETCH, "block_until_ms": 0}
    for field in ("summary", "retrieval_hint", "status", "task_type", "task_id", "output_file"):
        out = guard.raw(grok("PostToolUse", "run_terminal_command", launch, g_started(FETCH, **{field: ATTACK})), "--agent", "grok")
        assert out and ATTACK not in json.dumps(out), field
    for field in ("truncation_hint", "started", "status"):
        out = guard.raw(g_get(g_output(FETCH, BENIGN, **{field: ATTACK})), "--agent", "grok")
        assert out and ATTACK not in json.dumps(out), field


def test_grok_monitor_is_asked_about_and_the_question_keeps_groks_fields(guard):
    guard.configure(mode="block")
    monitor = {"command": f"while true; do {FETCH}; sleep 30; done", "description": "watch the feed", "persistent": True}
    out = guard.raw(grok("PreToolUse", "monitor", monitor), "--agent", "grok")["hookSpecificOutput"]
    assert out["permissionDecision"] == "ask" and out["updatedInput"]["persistent"] is True
    assert out["updatedInput"]["command"].split("\n")[:1] == ["# jevguard: OUTPUT CANNOT BE SCANNED"]
    assert guard.raw(grok("PreToolUse", "monitor", {"command": "tail -f app.log", "description": "watch"}), "--agent", "grok") is None
    assert guard.raw(grok("PreToolUse", "monitor", {"command": "jevguard gate off"}), "--agent", "grok")["hookSpecificOutput"]["permissionDecision"] == "ask"


# ---- Hermes: the process tool returns the output ---------------------------------------------------
def test_hermes_output_of_a_background_job_is_the_output_of_what_started_it(guard, monkeypatch):
    from jevguard.agents import hermes
    guard.configure(mode="block")
    monkeypatch.setenv("JEVGUARD_HOME", str(guard.home))
    ids = {"session_id": "h1"}
    started_job = json.dumps({"output": "", "session_id": "proc_7", "pid": 1})
    assert hermes.around("terminal", {"command": FETCH, "background": True}, lambda a: started_job, ids) == started_job
    poll = json.dumps({"status": "exited", "output": ATTACK})
    assert notice_in(hermes.around("process", {"action": "poll", "session_id": "proc_7"}, lambda a: poll, ids))
    assert guard.log()[-1]["native_tool"] == "process" and guard.log()[-1]["tool"] == "Bash"
    # another job, not known: judged by the command its result names
    named = json.dumps({"status": "exited", "command": FETCH, "output": ATTACK})
    assert notice_in(hermes.around("process_manage", {"action": "log", "session_id": "proc_9"}, lambda a: named, ids))
    local = json.dumps({"status": "exited", "command": "make test", "output": ATTACK})
    assert hermes.around("process", {"action": "log", "session_id": "proc_8"}, lambda a: local, ids) == local
