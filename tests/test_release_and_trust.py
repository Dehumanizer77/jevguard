"""Releasing a result that will never come back the same, and the list of trusted addresses."""

import fcntl
import json
import os
import threading
import time

import pytest

from conftest import ATTACK, BENIGN
from jevguard import cli, config, gate, provenance, store

BASH = {"stdout": "", "stderr": "", "interrupted": False, "isImage": False, "noOutputExpected": False}


def webfetch(text, url="https://news.example.com/article"):
    return {"bytes": 577, "code": 200, "codeText": "OK", "result": text, "durationMs": 1313, "url": url}


def read(path, text):
    return {"type": "text", "file": {"filePath": path, "content": text, "numLines": 3, "startLine": 1, "totalLines": 3}}


def fetch(guard, url, text, **kw):
    return guard.hook("PostToolUse", "WebFetch", {"url": url, "prompt": "summarise"}, webfetch(text, url), **kw)


def load(guard, monkeypatch):
    monkeypatch.setenv("JEVGUARD_HOME", str(guard.home))
    return config.load()


# ---- release hands the original over -------------------------------------------------------------
def test_notice_names_where_a_released_original_will_be(guard):
    guard.configure(mode="block")
    out = fetch(guard, "https://news.example.com/a", ATTACK)
    notice = json.loads(out["hookSpecificOutput"]["updatedToolOutput"]["result"])
    qid = notice["quarantine_id"]
    expected = str(guard.home / "released" / f"{qid}.txt")
    assert expected in notice["if_released"] and "owner" in notice["if_released"]
    assert not os.path.exists(expected)  # nothing is there until the owner releases it


def test_release_writes_the_original_and_the_agent_can_read_it(guard, jev, monkeypatch):
    guard.configure(mode="block")
    fetch(guard, "https://news.example.com/a", ATTACK)
    qid = guard.log()[-1]["quarantine_id"]
    cfg = load(guard, monkeypatch)
    digest, files = store.release(cfg, qid)
    copy = guard.home / "released" / f"{qid}.txt"
    assert files == [copy] and copy.read_text() == ATTACK and oct(copy.stat().st_mode)[-3:] == "600"
    # a fresh fetch of the same page gives different words: the release list does not cover it,
    # but the agent no longer needs it
    assert fetch(guard, "https://news.example.com/a", ATTACK + " (summarised differently this time)") is not None
    n = len(jev.requests)
    assert guard.hook("PostToolUse", "Read", {"file_path": str(copy)}, read(str(copy), ATTACK)) is None
    assert guard.hook("PostToolUse", "Read", {"file_path": str(copy), "offset": 2}, read(str(copy), ATTACK[40:])) is None
    assert len(jev.requests) == n  # read by the owner already; not sent for scoring again
    guard.configure(mode="block", scan_local=True)  # also when local files are scanned
    assert guard.hook("PostToolUse", "Read", {"file_path": str(copy)}, read(str(copy), ATTACK[40:])) is None
    assert len(jev.requests) == n


def test_release_through_the_command_prints_the_file(guard, monkeypatch, capsys):
    guard.configure(mode="block")
    fetch(guard, "https://news.example.com/a", ATTACK)
    qid = guard.log()[-1]["quarantine_id"]
    load(guard, monkeypatch)
    monkeypatch.setattr(cli, "_owner_only", lambda: True)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)
    assert cli.main(["release", qid]) == 0
    printed = capsys.readouterr().out
    assert str(guard.home / "released" / f"{qid}.txt") in printed and "released" in printed


def test_released_images_are_written_too(guard, monkeypatch):
    import base64
    png = bytes.fromhex("89504e470d0a1a0a") + b"not really a picture"
    guard.configure(mode="block", on_error="closed", skip_tools=[])
    guard.hook("PostToolUse", "mcp__shots__capture", {}, [{"type": "text", "text": ATTACK},
                                                         {"type": "image", "data": base64.b64encode(png).decode()}])
    qid = guard.log()[-1]["quarantine_id"]
    _, files = store.release(load(guard, monkeypatch), qid)
    assert [f.name for f in files] == [f"{qid}.txt", f"{qid}-1.png"] and files[1].read_bytes() == png


def test_a_download_into_the_released_directory_is_still_outside_content(guard, tmp_path):
    guard.configure(mode="block")
    target = str(guard.home / "released" / "page.txt")
    guard.hook("PostToolUse", "Bash", {"command": f"curl -s -o {target} https://news.example.com/a"}, dict(BASH), cwd="/work")
    assert guard.hook("PostToolUse", "Read", {"file_path": target}, read(target, ATTACK)) is not None


# ---- the list of what is in quarantine -----------------------------------------------------------
def owner(guard, monkeypatch):
    cfg = load(guard, monkeypatch)
    monkeypatch.setattr(cli, "_owner_only", lambda: True)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)
    return cfg


def test_quarantine_lists_every_entry_newest_first(guard, monkeypatch, capsys):
    guard.configure(mode="block")
    fetch(guard, "https://news.example.com/old", ATTACK)
    old = guard.log()[-1]["quarantine_id"]
    fetch(guard, "https://news.example.com/new", "Weather today. " + ATTACK)
    new = guard.log()[-1]["quarantine_id"]
    cfg = owner(guard, monkeypatch)
    os.utime(cfg.quarantine_dir / f"{old}.json", (1_700_000_000, 1_700_000_000))
    store.release(cfg, old)
    score = json.loads((cfg.quarantine_dir / f"{new}.json").read_text())["verdict"]["score"]
    assert cli.main(["quarantine"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith(new) and lines[1].startswith(old)
    assert "WebFetch" in lines[0] and "https://news.example.com/new" in lines[0] and f"{score:.2f}" in lines[0]
    assert "Weather today." in lines[0].split("|", 1)[1] and "released" not in lines[0]
    assert "released" in lines[1] and "https://news.example.com/old" in lines[1]
    assert lines[-1].startswith("2 in quarantine;")
    assert cli.main(["quarantine", "-n", "1"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith(new) and old not in "".join(lines) and lines[-1].startswith("2 in quarantine, the newest 1 shown")


def test_the_list_is_for_the_owner_only(guard, monkeypatch, capsys):
    """How each result begins is quarantined content too: an agent does not get it, as with show."""
    guard.configure(mode="block")
    fetch(guard, "https://news.example.com/a", ATTACK)
    load(guard, monkeypatch)
    assert cli.main(["quarantine"]) == 2  # no terminal here: the output would go to whoever ran it
    out = capsys.readouterr()
    assert ATTACK[:20] not in out.out and "Refused" in out.err


def test_control_characters_are_written_out_for_the_terminal(guard, monkeypatch, capsys):
    assert cli._printable("a\x1b[2Jb\rc‮d​e\nf\tg\x9bh\x07") == "a\\x1b[2Jb\\rc\\u202ed\\u200be\nf\tg\\x9bh\\x07"
    guard.configure(mode="block")
    fetch(guard, "https://news.example.com/a", "‮txt.exe \x1b]0;owned\x07Totally​ harmless\r\n" + ATTACK)
    qid = guard.log()[-1]["quarantine_id"]
    owner(guard, monkeypatch)
    for args in (["quarantine"], ["show", qid]):
        assert cli.main(args) == 0
        out = capsys.readouterr().out
        assert not any(c in out for c in "\x1b\x07\r​‮") and "\\u202etxt.exe" in out, args


# ---- discard, the opposite of release ------------------------------------------------------------
def quarantined(guard, url, text=ATTACK):
    fetch(guard, url, text)
    return guard.log()[-1]["quarantine_id"]


def test_discard_takes_a_release_back_and_the_content_is_blocked_again(guard, monkeypatch, capsys):
    guard.configure(mode="block")
    qid = quarantined(guard, "https://news.example.com/a")
    cfg = owner(guard, monkeypatch)
    _, files = store.release(cfg, qid)
    other = "abc123 fw-20261001-aaaaaa WebFetch released 2026-10-01\n"
    cfg.released_file.write_text("# kept by hand\n" + cfg.released_file.read_text() + other)
    assert fetch(guard, "https://news.example.com/a", ATTACK) is None  # released: it passes
    assert cli.main(["discard", qid]) == 0
    said = capsys.readouterr().out
    assert said.startswith(f"{qid}: discarded; its release taken back; deleted ") and str(files[0]) in said
    assert not (cfg.quarantine_dir / f"{qid}.json").exists() and not files[0].exists()
    assert cfg.released_file.read_text() == "# kept by hand\n" + other  # the other lines stay as they were
    assert files[0].name not in json.loads(cfg.released_manifest.read_text())
    assert fetch(guard, "https://news.example.com/a", ATTACK) is not None  # blocked again


def test_discard_an_entry_that_was_never_released(guard, monkeypatch, capsys):
    guard.configure(mode="block")
    qid = quarantined(guard, "https://news.example.com/a")
    cfg = owner(guard, monkeypatch)
    assert cli.main(["discard", qid]) == 0 and capsys.readouterr().out == f"{qid}: discarded\n"
    assert not (cfg.quarantine_dir / f"{qid}.json").exists() and not cfg.released_file.exists()
    assert cli.main(["discard", qid]) == 1 and "no such quarantine entry" in capsys.readouterr().err
    assert cli.main(["discard", "fw-1"]) == 1


def test_content_released_as_another_entry_stays_released(guard, monkeypatch, capsys):
    guard.configure(mode="block")
    first = quarantined(guard, "https://news.example.com/a")
    second = quarantined(guard, "https://news.example.com/a")
    cfg = owner(guard, monkeypatch)
    store.release(cfg, first)
    assert cli.main(["discard", second]) == 0 and f"still released as {first}" in capsys.readouterr().out
    assert fetch(guard, "https://news.example.com/a", ATTACK) is None


def test_discard_older_than_asks_first(guard, monkeypatch, capsys):
    guard.configure(mode="block")
    ids = [quarantined(guard, f"https://news.example.com/{n}", f"Item {n}. " + ATTACK) for n in range(3)]
    cfg = owner(guard, monkeypatch)
    now = time.time()
    for qid, days in zip(ids, (40, 10, 0)):
        os.utime(cfg.quarantine_dir / f"{qid}.json", (now - days * 86400,) * 2)
    store.release(cfg, ids[0])
    asked, answers = [], iter(["n", "y"])
    monkeypatch.setattr("builtins.input", lambda q: (asked.append(q), next(answers))[1])
    assert cli.main(["discard", "--older-than", "30d"]) == 1 and "nothing discarded" in capsys.readouterr().out
    assert asked == ["discard 1 quarantined result older than 30d, and take back the release of 1 of them? [y/N] "]
    assert all((cfg.quarantine_dir / f"{q}.json").exists() for q in ids) and ids[0] in store.released_ids(cfg)
    assert cli.main(["discard", "--older-than", "30d"]) == 0
    assert not (cfg.quarantine_dir / f"{ids[0]}.json").exists() and ids[0] not in store.released_ids(cfg)
    assert cli.main(["discard", "--older-than", "1w", "--yes"]) == 0 and len(asked) == 2
    assert [p.stem for p in cfg.quarantine_dir.glob("*.json")] == [ids[2]]
    capsys.readouterr()
    assert cli.main(["discard", "--older-than", "1w"]) == 0 and "nothing in quarantine is older than 1w" in capsys.readouterr().out


def test_discard_wants_entries_or_an_age(guard, monkeypatch, capsys):
    owner(guard, monkeypatch)
    assert cli.main(["discard"]) == 1
    assert cli.main(["discard", "fw-20261019-abcdef", "--older-than", "1d"]) == 1
    with pytest.raises(SystemExit):
        cli.main(["discard", "--older-than", "30x"])
    assert cli._age("1.5h") == (5400, "1.5h") and cli._age("2")[0] == 2 * 86400


def test_release_and_discard_check_every_id_before_acting_on_any(guard, monkeypatch, capsys):
    guard.configure(mode="block")
    first = quarantined(guard, "https://news.example.com/a", "First. " + ATTACK)
    second = quarantined(guard, "https://news.example.com/b", "Second. " + ATTACK)
    cfg = owner(guard, monkeypatch)
    typo = "fw-20261019-000000"
    assert cli.main(["release", first, typo, second]) == 1
    err = capsys.readouterr().err
    assert f"{typo}: no such quarantine entry" in err and "nothing released" in err
    assert not cfg.released_file.exists() and not (cfg.released_dir / f"{first}.txt").exists()
    assert cli.main(["release", first, second, first]) == 0  # each once
    assert sorted(store.released_ids(cfg)) == sorted([first, second]) and len(cfg.released_file.read_text().splitlines()) == 2
    capsys.readouterr()
    assert cli.main(["discard", first, typo, "nonsense"]) == 1
    err = capsys.readouterr().err
    assert f"{typo}: no such" in err and "nonsense: no such" in err and "nothing discarded" in err
    assert sorted(store.released_ids(cfg)) == sorted([first, second]) and (cfg.quarantine_dir / f"{first}.json").exists()


def test_discard_is_for_the_owner_only(guard, monkeypatch):
    """Emptying the quarantine would let an agent hide what it had been shown."""
    guard.configure(mode="block")
    qid = quarantined(guard, "https://news.example.com/a")
    cfg = load(guard, monkeypatch)
    assert cli.main(["discard", qid]) == 2 and (cfg.quarantine_dir / f"{qid}.json").exists()


def test_a_discard_that_stops_part_way_has_taken_the_release_back_first(guard, monkeypatch, tmp_path, capsys):
    guard.configure(mode="block")
    qid = quarantined(guard, "https://news.example.com/a")
    cfg = owner(guard, monkeypatch)
    store.release(cfg, qid)
    elsewhere = tmp_path / "elsewhere"
    cfg.released_dir.rename(elsewhere)
    cfg.released_dir.symlink_to(elsewhere)
    assert cli.main(["discard", qid]) == 1 and "symbolic link" in capsys.readouterr().err
    assert qid not in store.released_ids(cfg) and (elsewhere / f"{qid}.txt").exists()
    assert (cfg.quarantine_dir / f"{qid}.json").exists()  # kept: the owner can try again
    assert fetch(guard, "https://news.example.com/a", ATTACK) is not None


def at_once(monkeypatch, first, second) -> dict:
    """Run first until it writes its first file, then second until it has finished or found a lock
    held, then let both run to the end. Events, not sleeps, so the order is the same every time.
    Returns what each raised, by name."""
    paused, go, moved, errors = threading.Event(), threading.Event(), threading.Event(), {}
    write, flock = store._write_private, fcntl.flock

    def write_private(path, data, *mode):
        if threading.current_thread().name == "first" and not paused.is_set():
            paused.set()
            go.wait(10)
        write(path, data, *mode)

    def lock(fd, op):
        if threading.current_thread().name == "second":
            try:
                return flock(fd, op | fcntl.LOCK_NB)
            except BlockingIOError:
                moved.set()
        return flock(fd, op)

    def run(name, op):
        try:
            op()
        except Exception as exc:
            errors[name] = exc
        finally:
            if name == "second":
                moved.set()

    monkeypatch.setattr(store, "_write_private", write_private)
    monkeypatch.setattr(fcntl, "flock", lock)
    threads = [threading.Thread(target=run, args=(name, op), name=name) for name, op in (("first", first), ("second", second))]
    threads[0].start()
    assert paused.wait(10)
    threads[1].start()
    assert moved.wait(10)
    go.set()
    for t in threads:
        t.join(10)
    return errors


@pytest.mark.parametrize("first", ["release", "discard"])
def test_a_release_and_a_discard_at_once_leave_nothing_released(guard, monkeypatch, first):
    """Whichever is under way when the other begins, nothing of the release is left after the
    discard (#48). A release that had written its files must not put the content back on the list
    once the discard has taken it off; one that waited for a discard finds the entry gone."""
    guard.configure(mode="block")
    qid = quarantined(guard, "https://news.example.com/a")
    cfg = load(guard, monkeypatch)
    digest, _ = store.release(cfg, qid)
    ops = {"release": lambda: store.release(cfg, qid), "discard": lambda: store.discard(cfg, qid)}
    errors = at_once(monkeypatch, ops[first], ops["discard" if first == "release" else "release"])
    assert qid not in store.released_ids(cfg) and digest not in store.released(cfg)
    assert not (cfg.quarantine_dir / f"{qid}.json").exists() and not any(cfg.released_dir.iterdir())
    assert json.loads(cfg.released_manifest.read_text()) == {}
    assert fetch(guard, "https://news.example.com/a", ATTACK) is not None
    assert guard.log()[-1]["action"] != "passed-released"
    if first == "discard":
        assert str(errors.pop("second")) == "no longer in quarantine"
    assert errors == {}


# ---- trusted addresses ---------------------------------------------------------------------------
PREFIX = "https://docs.example.com/guide"


@pytest.mark.parametrize("url, trusted", [
    ("https://docs.example.com/guide", True),
    ("https://docs.example.com/guide/", True),
    ("https://docs.example.com/guide/hooks?x=1#top", True),
    ("https://DOCS.example.com/guide/hooks", True),
    ("https://docs.example.com:443/guide/hooks", True),
    ("https://docs.example.com/guide-2", False),
    ("https://docs.example.com/", False),
    ("https://docs.example.com/other/guide", False),
    ("http://docs.example.com/guide/hooks", False),
    ("https://docs.example.com:8443/guide/hooks", False),
    ("https://docs.example.com.evil.example/guide/hooks", False),
    ("https://docs.example.com@evil.example/guide/hooks", False),
    ("https://evil.example/https://docs.example.com/guide/", False),
    ("https://docs.example.com\\@evil.example/guide/", False),
    ("https://docs.example.com/guide/../../secret", False),
    ("https://docs.example.com/guide%2f..%2fother", False),
    ("https://user:pw@docs.example.com/guide/", False),
    ("ftp://docs.example.com/guide/", False),
    ("not a url", False),
])
def test_what_a_trusted_prefix_covers(url, trusted):
    assert provenance.trusted_source(url, [PREFIX]) is trusted


def test_trusted_address_is_scanned_and_logged_but_not_withheld(guard, jev):
    guard.configure(mode="block", on_error="closed", gate="ask-flagged", trusted_sources=[PREFIX])
    n = len(jev.requests)
    assert fetch(guard, PREFIX + "/hooks", ATTACK) is None
    rec = guard.log()[-1]
    assert len(jev.requests) == n + 1 and rec["mode"] == "trusted" and rec["action"] == "would-block"
    assert rec["score"] >= 0.38 and rec["quarantine_id"]
    # the session still counts as having seen something that scored as an injection
    ask = guard.hook("PreToolUse", "Bash", {"command": "git push origin main"})
    assert ask["hookSpecificOutput"]["permissionDecision"] == "ask"
    # anything else is withheld as before
    assert fetch(guard, "https://docs.example.com/guide-2", ATTACK, session="b") is not None
    assert fetch(guard, "https://news.example.com/a", ATTACK, session="b") is not None


def test_the_trusted_list_does_not_reach_shell_commands(guard):
    """It holds for WebFetch, where the address is a field of the call. What a shell command
    really fetches cannot be read off it, however plain it looks."""
    guard.configure(mode="block", trusted_sources=[PREFIX])

    def run(command, session):
        return guard.hook("PostToolUse", "Bash", {"command": command}, dict(BASH, stdout=ATTACK), session=session, cwd="/work")

    for n, command in enumerate((f"curl -s {PREFIX}/hooks", f"curl -s {PREFIX}/hooks | head -50",
                                 f"wget -qO- {PREFIX}/hooks", f"curl -s '{PREFIX}/hooks' 2>/dev/null")):
        assert run(command, f"s{n}") is not None, command
        assert guard.log()[-1]["mode"] == "external" and guard.log()[-1]["action"] == "blocked"


def test_trust_command_edits_the_list(guard, monkeypatch, capsys):
    cfg = load(guard, monkeypatch)
    before = json.loads(cfg.config_file.read_text())
    assert cli.main(["trust", PREFIX]) == 0
    assert config.load().trusted_sources == [PREFIX]
    assert cli.main(["trust", PREFIX]) == 0 and config.load().trusted_sources == [PREFIX]  # no duplicates
    assert cli.main(["trust", "docs.example.com"]) == 1 and config.load().trusted_sources == [PREFIX]
    assert cli.main(["trust", "https://user:pw@docs.example.com/"]) == 1
    assert cli.main(["untrust", PREFIX]) == 0 and config.load().trusted_sources == []
    after = json.loads(cfg.config_file.read_text())
    assert {k: v for k, v in after.items() if k != "trusted_sources"} == before  # other settings are left alone
    capsys.readouterr()


def test_changing_the_trusted_list_from_inside_claude_code_asks(guard, monkeypatch):
    for command in ("jevguard trust https://evil.example/", "jevguard untrust " + PREFIX,
                    "python3 -c \"import subprocess; subprocess.run(['jevguard', 'trust', 'https://evil.example/'])\""):
        out = guard.hook("PreToolUse", "Bash", {"command": command})
        assert out and out["hookSpecificOutput"]["permissionDecision"] == "ask", command
    assert gate.guard_change("Bash", {"command": "jevguard status"}, load(guard, monkeypatch)) == ""


def test_a_bad_entry_in_the_settings_is_an_error_not_a_silent_pass(guard, monkeypatch):
    load(guard, monkeypatch)
    (guard.home / "config" / "config.json").write_text(json.dumps({"trusted_sources": ["docs.example.com"]}))
    with pytest.raises(ValueError):
        config.load()
