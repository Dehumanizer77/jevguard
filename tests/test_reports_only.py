"""Commands whose output only reports on the agent's own work are scanned and never withheld.

That holds only for the forms that print nothing else. `cp notes.txt /dev/stdout` is a copy
command that prints a file; `date -f notes.txt` complains about every line of one.
"""

import os

import pytest

from conftest import ATTACK

BASH = {"stdout": "", "stderr": "", "interrupted": False, "isImage": False, "noOutputExpected": False}


def run(guard, command, cwd="/work"):
    guard.configure(mode="block", scan_local=True)
    out = guard.hook("PostToolUse", "Bash", {"command": command}, dict(BASH, stdout=f"{command!r} {ATTACK}"), cwd=cwd)
    return out, guard.log()[-1]["mode"]


@pytest.mark.parametrize("command", [
    "git status",
    "rtk git status --short --branch",
    "git add -A && git commit -q -m 'fix: verbose logging' && echo done",
    "git checkout -b fix && git add src && git commit -m x",
    "git switch main; git branch -D fix",
    "git --no-pager branch --show-current",
    "git tag -a v1.0 -m 'first release' && git rev-parse HEAD",
    "mkdir -p out && cp a.txt out/ && mv out/a.txt out/b.txt; echo $?",
    "cp a.txt b.txt 2>/dev/null; chmod 600 b.txt; rm -f a.txt",
    "date +%F; whoami; hostname; pwd",
    "wc -l notes.txt",
    "cd /tmp && touch x && ln -s x y",
])
def test_reports_on_the_agents_own_work_are_never_withheld(guard, command):
    out, mode = run(guard, command)
    assert out is None and mode == "warn", command


@pytest.mark.parametrize("command", [
    "cp notes.txt /dev/stdout",                        # a copy that prints the file
    "cp notes.txt /dev/fd/1",
    "cp notes.txt /proc/self/fd/1",
    "mv notes.txt /dev/stderr",
    "cp -t /dev/fd notes.txt",
    "cp --target-directory=/dev/fd notes.txt",
    "ln -s /dev/stdout out && cp notes.txt out",
    "date -f notes.txt",                               # "invalid date" for every line of the file
    "date -uf notes.txt",
    "date --file=notes.txt",
    "date --fi notes.txt",
    "wc --files0-from=list",
    "du --files0-from list",
    "./date",                                          # some other program called date
    "/tmp/tools/cp a b",
    "PATH=/tmp/tools date",
    "GIT_EDITOR=./x git commit",
    "git -c core.fsmonitor=./x status",                # git told to run a program
    "git --config-env=core.fsmonitor=X status",
    "git -C /tmp/elsewhere status",
    "git status -v",                                   # the staged changes, in full
    "git status --verb",
    "git commit -av -m x",
    "git commit -F notes.txt",                         # a message that is not written in the command
    "git commit --amend --no-edit",
    "git add -p",
    "git stash",                                       # prints the title of the last commit, whoever wrote it
    "git stash show -p",
    "git checkout v1.0",
    "git switch --detach v1.0",
    "git branch -vv",
    "git branch -r --format='%(contents)'",
    "git tag -n9",
    "git log -1",
    "echo $(cat notes.txt)",
    "echo *",                                          # file names can come from outside
    "wc -l < notes.txt",
    "echo done # cat notes.txt",
])
def test_the_forms_that_print_something_else_are_ordinary_local_output(guard, command):
    out, mode = run(guard, command)
    assert out is not None and mode == "local", command


def test_a_link_to_the_terminal_is_followed(guard, tmp_path):
    os.symlink("/dev/stdout", tmp_path / "out")
    (tmp_path / "sub").mkdir()
    os.symlink("/dev", tmp_path / "sub" / "devices")
    for command in ("cp notes.txt out", "cp notes.txt ./out", "cd sub && cp ../notes.txt ../out",
                    "cp notes.txt sub/devices/tty", f"cp notes.txt {tmp_path}/out"):
        out, mode = run(guard, command, cwd=str(tmp_path))
        assert out is not None and mode == "local", command
    out, mode = run(guard, "cp notes.txt copy.txt", cwd=str(tmp_path))
    assert out is None and mode == "warn"


def test_a_command_the_owner_listed_is_held_to_the_same_form(guard):
    guard.configure(mode="block", scan_local=True, trusted_commands=["make"])
    result = dict(BASH, stdout=ATTACK)
    assert guard.hook("PostToolUse", "Bash", {"command": "make test"}, result) is None
    assert guard.log()[-1]["mode"] == "warn"
    for command in ("./make test", "make test > /dev/null; cp notes.txt /dev/stdout", "make test < notes.txt"):
        guard.configure(mode="block", scan_local=True, trusted_commands=["make"])
        assert guard.hook("PostToolUse", "Bash", {"command": command}, dict(BASH, stdout=command + ATTACK)) is not None
