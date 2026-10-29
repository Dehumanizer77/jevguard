"""The approval question has to be rare and readable. On the first live days most questions
were false alarms: the check for administration commands matched the word "jevguard" followed,
anywhere within eighty characters, by a word like "gate" or "release". The package directory is
called jevguard/ and has a gate.py in it."""

import os

import pytest

from conftest import BENIGN

HOME = os.path.expanduser("~")


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
    "jevguard quarantine",
    "jevguard quarantine -n 5 | head",
    "jevguard discard fw-20261009-abcdef",
    "jevguard discard --older-than 1d -y",
    "bash -c 'jevguard mode log'",
    "python3 -c \"import os; os.system('jevguard uninstall')\"",
    "python3 -c \"import subprocess; subprocess.run(['/opt/jevguard/bin/jevguard', 'release', 'fw-20261009-abcdef'])\"",
    "python3 -c 'import subprocess; subprocess.run([\"jevguard\", \"mode\", \"log\"])'",
    "python3 -m jevguard.cli mode log",
    "cat > notes.md <<'EOF'\nthen run jevguard install to finish\nEOF",
])
def test_administration_commands_are_still_asked_about(guard, command):
    assert ask_reason(guard, command) != "", command


# Asked about on 2026-10-27 as "ssh is given a text that mentions /home/me": the $HOME and ~ of
# a script ssh runs on another host were filled in with this machine's.
REMOTE_SCRIPT = r"""timeout 60 ssh -o BatchMode=yes server.example 'bash -s' <<'EOF' 2>&1 | cut -c1-230
tmux list-panes -a -F "#{pane_pid}|#{pane_current_path}" 2>/dev/null | while IFS="|" read pid path; do
  mp=$(tr "\0" "\n" < /proc/$pid/environ 2>/dev/null | sed -n "s/^FNM_MULTISHELL_PATH=//p")
  echo "$pid cwd=${path/#$HOME/~} fnm=${mp:-none}"
done
EOF"""


@pytest.mark.parametrize("command", [
    REMOTE_SCRIPT,
    "ssh server.example 'echo $HOME'",
    f"ssh server.example 'ls {HOME} /home /'",
    "ssh server.example 'du -sh $HOME'",
    "ssh -qo BatchMode=yes server.example -v -- ls '$HOME'",
    "ssh server.example <<< 'cd ~ && ls ${HOME}/..'",
    "ssh server.example 'bash -s' <<< 'du -sh ~'",
    "ssh -p 2222 -l deploy server.example 'echo $HOME'",
    "ssh -l '' server.example 'echo $HOME'",  # a quoted "" is a word
    # where the other host's commands start is theirs: this command's directory stays /work
    "ssh server.example 'cd ~ && ls'; touch .",
    "ssh server.example ls; touch \"$PWD\" build",
])
def test_the_home_named_in_what_ssh_runs_on_another_host_is_that_hosts(guard, command):
    assert ask_reason(guard, command) == "", command


@pytest.mark.parametrize("command", [
    # what is in that home still counts: the host may be this one, or share its home
    "ssh server.example 'cat ~/.claude/settings.json'",
    "ssh server.example <<< 'ls $HOME/.claude'",
    # ssh's options and redirections take effect here
    "ssh -o 'LocalCommand=ls $HOME' -o PermitLocalCommand=yes server.example",
    "ssh -oLocalCommand='ls $HOME' -oPermitLocalCommand=yes server.example",
    "ssh server.example -o 'LocalCommand=ls $HOME' -o PermitLocalCommand=yes true",
    "ssh -E ~/.claude/settings.json server.example true",
    "ssh server.example true > ~/.claude/settings.json",
    # which word is the destination cannot be told: one may vanish or split (#72)
    "ssh $opts server.example 'echo $HOME'",
    "ssh -Z server.example 'echo $HOME'",
    "empty=; ssh -F /dev/null -l $empty deploy server.example -o 'ProxyCommand=touch $HOME' true",
    "ssh server.example $empty -oProxyCommand='touch $HOME' true",
    "ssh -l deploy* server.example -o 'ProxyCommand=touch $HOME' true",
    "ssh -l {deploy,x} server.example -o 'ProxyCommand=touch $HOME' true",
    'ssh server.example "du -sh $HOME"',
])
def test_what_ssh_does_here_is_still_asked_about(guard, command):
    assert ask_reason(guard, command) != "", command


@pytest.mark.parametrize("command", [
    # the host may be this one: a change to the home there is asked about as one here (#73)
    "ssh localhost 'touch \"$HOME\"'",
    "ssh server.example 'cd && touch .'",
    "ssh server.example 'bash -s' <<< 'touch $HOME'",
    "ssh server.example <<'EOF'\ntouch ~/..\nEOF",
    "ssh server.example 'bash -c \"touch ~\"'",
    # where it starts: in the home, with PWD set there, not in this command's directory (/work)
    "ssh localhost 'echo \"$HOME\"; touch \"$PWD\"'",
    "ssh localhost 'touch .'",
    "ssh localhost 'bash -s' <<< 'touch \"$PWD\"'",
    "ssh localhost <<'EOF'\ntouch ..\nEOF",
    "HOME=/tmp/x PWD=/tmp/x ssh localhost 'touch \"$HOME\" \"$PWD\"'",
    "cd /srv && ssh localhost 'touch .'",
    # what ssh sends to a program that is not a shell is not read as commands: it counts as before
    f"ssh server.example python3 - <<< 'import os; os.utime(\"{HOME}\")'",
    f"ssh server.example 'bash script.sh' <<< '{HOME}'",
])
def test_what_ssh_runs_on_another_host_is_read_as_if_it_ran_here(guard, command):
    assert ask_reason(guard, command) != "", command


@pytest.mark.parametrize("command", [
    # bash sets $_ to ssh's last word: the home, though ssh is not asked about for it (#71)
    f'ssh server.example {HOME}; read p <<< "$_"; touch "$p"',
    'ssh server.example "$HOME"; read p <<< "$_"; touch "$p"',
    # and what the other host prints may be this one's home
    "p=$(ssh localhost 'echo $HOME'); touch \"$p\"",
])
def test_the_home_ssh_is_given_reaches_a_program_given_a_value_later(guard, command):
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
