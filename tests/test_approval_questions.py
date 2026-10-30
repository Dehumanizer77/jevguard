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
    "trap 'touch .' EXIT; ssh server.example 'cd ~ && ls'",
    "ssh server.example \"cd ~; trap 'ls' EXIT\"; touch build",
    # what a program there that is not a shell reads from a pipe is data
    "echo hi | ssh server.example 'cat > /srv/x'",
    "tar c src | ssh server.example 'tar x -C /srv'",
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
    # and what that shell leaves to run at its end runs there too
    "ssh localhost \"trap 'touch .' EXIT\"",
    "ssh localhost \"f() { touch .; }; trap f EXIT\"",
    "ssh localhost \"cd Downloads; trap 'touch ..' EXIT\"",
    "ssh localhost 'bash -s' <<< \"trap 'touch .' EXIT\"",
    "ssh localhost <<'EOF'\ntrap 'touch \"$PWD\"' EXIT\ncd /srv\nEOF",
    # also where the command's beginning is not certain: reading it only adds
    "ssh localhost 'touch . *.log'",
    "ssh localhost \"touch . $unknown\"",
    "ssh -l $empty localhost 'touch .'",
    # a shell there that reads its commands from a pipe: what they are cannot be read
    "echo 'touch .' | ssh localhost",
    "cat script.sh | ssh localhost 'bash -s'",
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


@pytest.mark.parametrize("command", [
    # run here: ssh starts them with the user's shell, in this command's directory
    "ssh -o ProxyCommand='touch ~' server.example",
    "ssh -oLocalCommand='touch ~' -oPermitLocalCommand=yes server.example",
    "ssh -qo KnownHostsCommand='touch ~' server.example",
    "ssh -o 'LocalCommand touch %d' -o PermitLocalCommand=yes server.example",  # %d: the home
    "cd ~ && ssh -o ProxyCommand='touch .' server.example",
    "scp -o ProxyCommand='touch ~' notes.txt server.example:notes.txt",
    "sftp -o ProxyCommand='touch ~' server.example",
    "rsync -a -e \"ssh -o ProxyCommand='touch ~'\" src server.example:dst",
    "rsync -a --rsh=\"ssh -o ProxyCommand='touch ~'\" src server.example:dst",
    "RSYNC_RSH=\"ssh -o ProxyCommand='touch ~'\" rsync -a src server.example:dst",
    # run on the other host, which starts in the home
    "ssh -o RemoteCommand='touch ~' localhost",
    "ssh -o 'RemoteCommand touch .' localhost",
    "ssh -o remotecommand='touch .' localhost",
    "rsync -a --rsync-path='touch .; rsync' src localhost:dst",
])
def test_command_lines_given_in_ssh_and_rsync_options_are_read_as_commands(guard, command):
    assert ask_reason(guard, command) != "", command


@pytest.mark.parametrize("command", [
    "ssh -o ProxyCommand='nc %h %p' server.example",
    "ssh -o ProxyCommand='ssh -W %h:%p jump.example' server.example",
    "ssh -o 'ProxyCommand touch .' server.example",  # here, in /work
    "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null server.example uptime",
    "scp -o BatchMode=yes notes.txt server.example:notes.txt",
    "rsync -a -e 'ssh -p 2222' src server.example:dst",
])
def test_ordinary_ssh_and_rsync_options_are_not_asked_about(guard, command):
    assert ask_reason(guard, command) == "", command


LOCAL_SCRIPT = REMOTE_SCRIPT.replace("timeout 60 ssh -o BatchMode=yes server.example 'bash -s'", "bash -s")


@pytest.mark.parametrize("command", [
    # read as commands, as if typed in place of the shell: the home they name is not the shell's change
    LOCAL_SCRIPT,
    "bash -c 'echo $HOME'",
    "bash <<< 'ls $HOME /home'",
    "sh -c 'du -sh ~'",
    "bash -lc 'ls ~ $HOME'",
    # every option comes before the script, also one after -c, and -o and -O take a value (#77, #78)
    "bash -c -x 'echo $HOME'",
    "bash -O extglob -c 'ls $HOME'",
    "bash -eo pipefail -c 'du -sh ~'",
    "bash --norc -c 'echo $HOME'",
    # what it prints goes nowhere that runs it
    "bash -c 'du -sh ~' | sort -h | head",
    "bash -c 'ls $HOME' > /dev/null",
])
def test_a_script_given_to_a_shell_here_is_read_as_its_commands(guard, command):
    assert ask_reason(guard, command) == "", command


@pytest.mark.parametrize("command", [
    # a script operand or -- ends the shell's options: the -c after it is the script's own (#77)
    f"bash notes.sh -c {HOME}",
    f"bash -- notes.sh -c {HOME}",
    f"bash notes.sh -lc {HOME}",
    f"bash -x notes.sh -c {HOME}",
    f"sh - -c {HOME}",
])
def test_an_argument_after_a_script_is_the_scripts_and_not_a_command(guard, command):
    assert ask_reason(guard, command) != "", command


@pytest.mark.parametrize("command", [
    # the home a script names counts for the shell or ssh that runs it whenever the script does more
    # than read: it may write it into a file and run that (#78, #79), or hand it to a program
    "bash -c 'echo touch $HOME > s.sh; bash -e s.sh'",
    "bash -c 'echo touch $HOME > s.sh; bash -O extglob s.sh'",
    "bash -c 'echo touch $HOME > s.sh; bash -o errexit s.sh'",
    "bash -c 'echo touch $HOME | tee s.sh; bash s.sh'",
    "bash -c 'echo touch $HOME | sed -n \"w s.sh\"; bash s.sh'",
    "bash -c 'echo touch $HOME > s.sh; chmod +x s.sh; ./s.sh'",
    "bash -c 'echo \"all:; touch $HOME\" > Makefile; make'",
    "ssh localhost 'echo touch $HOME | tee s.sh; bash s.sh'",
    "ssh localhost 'echo touch $HOME > s.sh; bash -e s.sh'",
    # programs that run what they are given, though they look like they only read
    "bash -c 'rg --pre \"touch $HOME\" x .'",
    "bash -c 'sed -n \"1e touch $HOME\" /etc/hostname'",
    "bash -c 'tmux list-panes -F \"#(touch $HOME)\"'",
    "bash -c 'sort --compress-program=./x $HOME'",
    # a value bash reads as arithmetic, where a subscript runs what is in it
    "bash -c 'x=\"a[\\$(touch \\$HOME)]\"; test \"$x\" -eq 1'",
    "bash -c 'x=\"a[\\$(touch \\$HOME)]\"; printf \"%d\" \"$x\"'",
    # variables that programs and the shell take as instructions
    "bash -xc 'PS4=\"\\$(touch \\$HOME)\"; ls'",
    "bash -c 'LD_PRELOAD=./x.so ls $HOME'",
    "BASH_ENV=./x.sh bash -c 'ls $HOME'",
    # what the script prints, into a file or a program that does more than read
    "bash -c 'echo touch $HOME' | tee s.sh",
    "bash -c 'echo $HOME' | python3 -c 'import sys'",
    "ssh server.example 'du -sh $HOME' > report.txt",
])
def test_the_home_a_script_names_counts_where_the_script_may_hand_it_on(guard, command):
    assert ask_reason(guard, command) != "", command


@pytest.mark.parametrize("command", [
    "bash -c 'touch $HOME'",
    "sh <<< 'touch ~'",
    "bash -c 'cd; touch .'",
    "bash -c 'cat ~/.claude/settings.json'",  # a file in the home still counts for the shell
    f"bash notes.sh <<< '{HOME}'",  # what a script reads is data, not commands
    "bash $opts -c 'echo $HOME'",  # which word is the script cannot be told
])
def test_what_a_shell_runs_here_is_still_asked_about(guard, command):
    assert ask_reason(guard, command) != "", command


@pytest.mark.parametrize("command", [
    # a script the command makes, in a <(...) or a file it writes, is given what the command names
    "source <(echo touch $HOME)",
    ". <(echo touch $HOME)",
    "bash <(echo touch $HOME)",
    "echo touch $HOME > s.sh; bash s.sh",
    "echo touch $HOME > s.sh; sh < s.sh",
    f"echo 'import os; os.utime(\"{HOME}\")' > s.py && python3 s.py",
    # and so wrapped in a shell or sent to another host, where only the shell's own words counted
    "bash -c 'source <(echo touch $HOME)'",
    "bash -c 'echo touch $HOME > s.sh; bash s.sh'",
    "ssh localhost 'source <(echo touch $HOME)'",
    # whatever options the shell or interpreter is given before the file (#78)
    "echo touch $HOME > s.sh; bash -e s.sh",
    "echo touch $HOME > s.sh; bash -O extglob s.sh",
    "echo touch $HOME > s.sh; bash -o errexit < s.sh",
    f"echo 'import os; os.utime(\"{HOME}\")' > s.py && python3 -W ignore s.py",
    # and whichever program wrote the file (#79)
    "echo touch $HOME | tee s.sh; bash s.sh",
    "echo touch $HOME | dd of=s.sh; bash s.sh",
    "echo touch $HOME > a; cp a s.sh; bash s.sh",
    # run by its path, or read from the pipe through a file name
    "echo touch $HOME > s.sh; chmod +x s.sh; ./s.sh",
    f"echo 'import os; os.utime(\"{HOME}\")' | python3 /dev/stdin",
])
def test_a_script_the_command_makes_and_runs_is_given_what_the_command_names(guard, command):
    assert ask_reason(guard, command) != "", command


@pytest.mark.parametrize("command", [
    "echo touch $HOME | bash -s -- -c",  # -c after -- is an argument: bash reads the pipe
    "echo touch $HOME | bash /dev/stdin -c x",
    "echo touch $HOME | bash -sc 'echo hi'",  # dash runs both
    # also inside a part of the pipeline, where its input is the pipe's
    "echo touch $HOME | (bash)",
    "echo touch $HOME | { sh -s; }",
    "echo touch $HOME | while read l; do bash; done",
    "bash -c 'echo touch $HOME' | (bash)",
    "ssh server.example 'echo touch $HOME' | (sh)",
])
def test_a_shell_that_reads_its_commands_from_a_pipe_is_asked_about(guard, command):
    assert ask_reason(guard, command) != "", command


@pytest.mark.parametrize("command", [
    "find . -name '*.sh' | while read f; do bash \"$f\"; done",  # each script reads the pipe as data
    "printf 'y\\n' | (cd sub && bash -c 'read a; echo $a')",
    "git log --oneline | head -5",
])
def test_a_shell_that_reads_data_from_a_pipe_is_not_asked_about(guard, command):
    assert ask_reason(guard, command) == "", command


@pytest.mark.parametrize("command", [
    "diff <(sort a) <(sort b)",
    "cat > s.sh <<'EOF'\nset -e\nmake build\nEOF\nbash s.sh",
    "bash scripts/test.sh",
    "source .venv/bin/activate && pytest",
    "python3 -m pytest tests -q",
])
def test_scripts_that_name_nothing_of_the_guard_are_not_asked_about(guard, command):
    assert ask_reason(guard, command) == "", command


# Asked about on 2026-10-29 as "python3 is given a text that mentions /, a directory that holds the
# guard's files": a test case in a script, `${p//a\\//}`, was read as an expansion the shell left
# in, and what follows its last / as an argument of its own. In a text a lone / or ~ names nothing.
@pytest.mark.parametrize("command", [
    "python3 - <<'EOF'\ncases = ['p=a/b; touch ${p//a\\\\//}']\nEOF",
    "python3 -c 'print(\"${x:-/}\", \"${x:-~}\", \"${x/a/~}\")'",
    "git commit -m 'Read ${p:-/} and ${p//x/~} as bash reads them'",
    "gh pr create --title x --body 'In `${p//x//}` the third / starts what is put in'",
])
def test_a_lone_slash_in_an_expansion_inside_a_script_names_no_directory(guard, command):
    assert ask_reason(guard, command) == "", command


@pytest.mark.parametrize("command", [
    # an argument of its own: the expansion is the shell's
    "touch ${x:-/}",
    "touch \"${x:-~}\"",
    "touch ${x/a/~}",
    # a path in it, inside a text
    "python3 -c 'import os; os.utime(\"${x:-~/.claude}\")'",
    "python3 -c 'import os; os.utime(\"${x/a/~/.claude/settings.json}\")'",
    f"python3 - <<EOF\nimport os; os.utime('${{d:-{HOME}/.claude}}')\nEOF",
])
def test_a_path_in_an_expansion_is_still_asked_about(guard, command):
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
