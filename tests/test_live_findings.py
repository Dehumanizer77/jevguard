"""Things the first live day showed that no review had: after a few hours one session was
treating ordinary local output as outside content, because names that were never real files
had been recorded as downloads and then matched as words in later output."""

from conftest import ATTACK

BASH = {"stdout": "", "stderr": "", "interrupted": False, "isImage": False, "noOutputExpected": False}


def bash(text):
    return dict(BASH, stdout=text)


def read(path, text):
    return {"type": "text", "file": {"filePath": path, "content": text, "numLines": 3, "startLine": 1, "totalLines": 3}}


def run(guard, command, output="", cwd="/work"):
    return guard.hook("PostToolUse", "Bash", {"command": command}, bash(output), cwd=cwd)


def test_a_download_named_like_a_common_word_does_not_claim_every_output(guard, jev):
    guard.configure(mode="block")
    run(guard, "curl -s -o main https://news.example.com/a")
    n = len(jev.requests)
    # the word in a sentence, in a branch list, in a path of another file: not that file
    for command, output in (("git status", "On branch main\nnothing to commit, working tree clean\n" + ATTACK),
                            ("git log --oneline -1", "abc1234 Merge branch main into feature\n" + ATTACK),
                            ("cat src/main.py", "def main():\n    pass\n" + ATTACK),
                            ("git push", "To github.com:a/b.git\n   abc..def  main -> main\n" + ATTACK)):
        assert run(guard, command, output) is None, command
    assert len(jev.requests) == n
    # where a listing or a search prints the file itself, the result is outside content
    for command, output in (("grep -rn instructions .", "main:3:" + ATTACK),
                            ("grep -rn instructions .", "./main:3:" + ATTACK),
                            ("rg -n instructions", "main\n3:" + ATTACK),
                            ("cat main", ATTACK)):
        assert run(guard, command, output) is not None, (command, output[:20])


def test_only_files_that_exist_afterwards_are_tracked(guard, jev, tmp_path):
    guard.configure(mode="block", track_missing_files=False)
    work = tmp_path / "work"
    work.mkdir()
    (work / "page.html").write_text("saved by curl")
    # -o page.html was written; "pid" is an option value of ps, not a file
    run(guard, "curl -s -o page.html https://news.example.com/a && ps -o pid", cwd=str(work))
    assert guard.hook("PostToolUse", "Read", {"file_path": str(work / "page.html")},
                      read(str(work / "page.html"), ATTACK), cwd=str(work)) is not None
    n = len(jev.requests)
    assert run(guard, "echo pid", "pid 4242 " + ATTACK, cwd=str(work)) is None
    assert run(guard, "ls", "pid\nnotes.md\n" + ATTACK, cwd=str(work)) is None
    assert len(jev.requests) == n
    # a download that was deleted again is no longer anything
    (work / "page.html").unlink()
    assert run(guard, "ls", "page.html\n" + ATTACK, cwd=str(work)) is None
    assert len(jev.requests) == n


def test_a_directory_a_command_merely_runs_in_is_not_a_download(guard, jev, tmp_path):
    guard.configure(mode="block", track_missing_files=False)
    work = tmp_path / "work"
    (work / "repo").mkdir(parents=True)
    (work / "vendor").mkdir()
    (work / "repo" / "notes.md").write_text("mine")
    (work / "vendor" / "README.md").write_text("from the archive")
    run(guard, "curl -sL https://news.example.com/a.tgz | tar xz -C vendor && git -C repo log -1", cwd=str(work))
    n = len(jev.requests)
    mine = str(work / "repo" / "notes.md")
    assert guard.hook("PostToolUse", "Read", {"file_path": mine}, read(mine, ATTACK), cwd=str(work)) is None
    assert len(jev.requests) == n  # git -C repo: the repository is not what was downloaded
    theirs = str(work / "vendor" / "README.md")
    assert guard.hook("PostToolUse", "Read", {"file_path": theirs}, read(theirs, ATTACK), cwd=str(work)) is not None
