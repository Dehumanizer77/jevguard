"""Releasing a result that will never come back the same, and the list of trusted addresses."""

import json
import os

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
