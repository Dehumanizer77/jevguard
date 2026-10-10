"""The approval question has to be rare and readable. On the first live days most questions
were false alarms: the check for administration commands matched the word "jevguard" followed,
anywhere within eighty characters, by a word like "gate" or "release". The package directory is
called jevguard/ and has a gate.py in it."""

import pytest

from conftest import BENIGN


def ask_reason(guard, command, description="", cwd="/work", tool="Bash"):
    tool_input = {"command": command}
    if description:
        tool_input["description"] = description
    out = guard.hook("PreToolUse", tool, tool_input, cwd=cwd)
    return out["hookSpecificOutput"]["permissionDecisionReason"] if out else ""


@pytest.mark.parametrize("command", [
    # every one of these was asked about on 2026-10-09 and 2026-10-10
    'grep -n "def guard_change" -A 62 jevguard/gate.py | sed -n \'1,80p\'',
    "sed -i '40s/\"release\", \"show\"}/\"release\", \"show\", \"trust\"}/' jevguard/gate.py && sed -n '40p;42p' jevguard/gate.py",
    "sed -i '63s/if mode == \"external\":/if mode in (\"external\", \"trusted\"):/' jevguard/hook.py",
    "gh pr create --repo Dehumanizer77/jevguard --base main --head release-handover-and-trusted-sources --title x",
    # and their relatives
    "gh issue list --repo Dehumanizer77/jevguard --state open",
    "git clone https://github.com/Dehumanizer77/jevguard release-notes",
    "cd jevguard && grep -rn mode .",
    "python3 -m pytest tests -q -k 'gate or release or install'",
    "git log --oneline -- jevguard/gate.py jevguard/cli.py",
    "git show HEAD:jevguard/gate.py | head",
    "pip show jevguard",
    "ls jevguard tests",
    "jevguard status",
    "jevguard log --all -n 20",
    "jevguard scan notes.txt",
])
def test_working_on_a_project_called_jevguard_is_not_changing_the_guard(guard, command):
    assert ask_reason(guard, command) == "", command


@pytest.mark.parametrize("command", [
    "jevguard mode log",
    "jevguard gate off",
    "jevguard uninstall",
    "~/.local/share/jevguard/bin/jevguard install",
    "jevguard --settings /tmp/s.json install",
    "jevguard --settings=/tmp/s.json uninstall",
    "rtk jevguard release fw-20261009-abcdef",
    "bash -c 'jevguard mode log'",
    "python3 -c \"import os; os.system('jevguard uninstall')\"",
    "python3 -c \"import subprocess; subprocess.run(['/opt/jevguard/bin/jevguard', 'release', 'fw-20261009-abcdef'])\"",
    "python3 -c 'import subprocess; subprocess.run([\"jevguard\", \"mode\", \"log\"])'",
    "python3 -m jevguard.cli mode log",
    "cat > notes.md <<'EOF'\nthen run jevguard install to finish\nEOF",
])
def test_administration_commands_are_still_asked_about(guard, command):
    assert ask_reason(guard, command) != "", command


def test_the_question_says_what_the_agent_claims_the_call_is_for(guard):
    reason = ask_reason(guard, "jevguard mode log", description="Switch the guard to log mode as you asked")
    assert 'Claude describes the call as: "Switch the guard to log mode as you asked"' in reason
    assert "its own words, not checked" in reason and reason.startswith("jevguard: asking because ")
    # a long description is cut, a missing one leaves no empty quotes
    reason = ask_reason(guard, "jevguard mode log", description="x" * 400)
    assert "x" * 140 in reason and "x" * 141 not in reason
    assert "describes the call" not in ask_reason(guard, "jevguard mode log")
    # the same sentence in the question about a risky action after outside content
    guard.configure(gate="ask-external")
    guard.hook("PostToolUse", "WebFetch", {"url": "https://news.example.com/a"},
               {"bytes": 1, "code": 200, "codeText": "OK", "result": BENIGN, "durationMs": 1, "url": "https://news.example.com/a"})
    reason = ask_reason(guard, "git push origin main", description="Push the fix")
    assert "git push" in reason and 'Claude describes the call as: "Push the fix"' in reason
