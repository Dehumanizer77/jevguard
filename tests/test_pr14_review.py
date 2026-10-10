"""Regression tests for the review of pull request 14 (issues 15 to 18)."""

import base64
import json
import os

import pytest

from conftest import ATTACK, BENIGN
from jevguard import config, github, provenance, store

BASH = {"stdout": "", "stderr": "", "interrupted": False, "isImage": False, "noOutputExpected": False}
PREFIX = "https://docs.example.com/guide"
OWN = ["acme/*"]


def read(path, text):
    return {"type": "text", "file": {"filePath": path, "content": text, "numLines": 3, "startLine": 1, "totalLines": 3}}


def run(guard, command, output, **kw):
    return guard.hook("PostToolUse", "Bash", {"command": command}, dict(BASH, stdout=output), cwd="/work", **kw)


def asks(out) -> bool:
    return bool(out) and out["hookSpecificOutput"].get("permissionDecision") == "ask"


def released(guard, monkeypatch, text=ATTACK, images=()):
    """Quarantine a result and release it the way the owner's command does; returns its files."""
    guard.configure(mode="block", scan_local=True, on_error="closed", skip_tools=[])
    blocks = [{"type": "text", "text": text}] + [{"type": "image", "data": base64.b64encode(i).decode()} for i in images]
    guard.hook("PostToolUse", "mcp__mail__read", {}, blocks)
    monkeypatch.setenv("JEVGUARD_HOME", str(guard.home))
    return store.release(config.load(), guard.log()[-1]["quarantine_id"])[1]


# ---- #15 only what the owner released is exempt, and only while it is unchanged -------------------
def test_issue15_a_file_merely_placed_in_the_released_directory_is_scanned(guard, jev, monkeypatch):
    released(guard, monkeypatch)
    stray = guard.home / "released" / "not-approved.txt"
    stray.write_text(ATTACK)
    assert guard.hook("PostToolUse", "Read", {"file_path": str(stray)}, read(str(stray), ATTACK + " other")) is not None
    assert guard.log()[-1]["mode"] == "external"


def test_issue15_the_same_holds_for_commands_and_searches(guard, monkeypatch):
    original = released(guard, monkeypatch)[0]
    folder = guard.home / "released"
    stray = folder / "not-approved.txt"
    stray.write_text(ATTACK)
    for n, command in enumerate((f"cat {stray}", f"cd {folder} && cat *", f"grep -r instructions {folder}",
                                 f"cat {original}")):  # only Read is exempt, and only for a released original
        assert run(guard, command, f"{n} {ATTACK}") is not None, command
        assert guard.log()[-1]["mode"] == "external"
    grep = {"mode": "content", "numFiles": 1, "filenames": [str(stray)], "content": f"{stray}:1:{ATTACK}", "numLines": 1}
    assert guard.hook("PostToolUse", "Grep", {"pattern": "instructions", "path": str(guard.home)}, grep) is not None
    # a text that only names the directory, as the README does, is not its content
    run(guard, "cat README.md", f"released originals are written to {folder}/<id>.txt for the agent to read")
    assert guard.log()[-1]["mode"] == "local"


def test_issue15_an_edited_original_is_scanned(guard, monkeypatch):
    original = released(guard, monkeypatch)[0]
    assert guard.hook("PostToolUse", "Read", {"file_path": str(original)}, read(str(original), ATTACK)) is None
    original.write_text(ATTACK + " and now something the owner never read")
    out = guard.hook("PostToolUse", "Read", {"file_path": str(original)}, read(str(original), original.read_text()))
    assert out is not None


def test_issue15_a_partial_read_of_an_unchanged_original_passes(guard, jev, monkeypatch):
    original = released(guard, monkeypatch)[0]
    n = len(jev.requests)
    assert guard.hook("PostToolUse", "Read", {"file_path": str(original), "offset": 2, "limit": 1},
                      read(str(original), ATTACK[30:60])) is None
    assert len(jev.requests) == n


def test_issue15_released_images_are_checked_the_same_way(guard, monkeypatch):
    png = bytes.fromhex("89504e470d0a1a0a") + b"not really a picture"
    files = released(guard, monkeypatch, images=[png])
    image = {"type": "image", "file": {"base64": base64.b64encode(png).decode(), "type": "image/png"}}
    assert guard.hook("PostToolUse", "Read", {"file_path": str(files[1])}, image) is None
    files[1].write_bytes(png + b" edited")
    edited = {"type": "image", "file": {"base64": base64.b64encode(png + b" edited").decode(), "type": "image/png"}}
    assert guard.hook("PostToolUse", "Read", {"file_path": str(files[1])}, edited) is not None


def test_issue15_changing_the_released_directory_asks(guard, monkeypatch):
    original = released(guard, monkeypatch)[0]
    folder = str(guard.home / "released")
    for tool, tool_input in (("Write", {"file_path": f"{folder}/not-approved.txt", "content": "x"}),
                             ("Write", {"file_path": str(original), "content": "x"}),
                             ("Edit", {"file_path": str(original)}),
                             ("Bash", {"command": f"echo x > {original}"}),
                             ("Bash", {"command": f"cp /tmp/evil.txt {folder}/"}),
                             ("Bash", {"command": f"cd {folder} && rm *.txt"}),
                             ("Bash", {"command": f"ln -sf /tmp/evil.txt {original}"})):
        assert asks(guard.hook("PreToolUse", tool, tool_input)), (tool, tool_input)
    assert guard.hook("PreToolUse", "Bash", {"command": f"cat {original}"}) is None  # looking is not a change


def test_issue15_release_does_not_write_through_a_planted_link(guard, monkeypatch, tmp_path):
    guard.configure(mode="block", skip_tools=[])
    guard.hook("PostToolUse", "mcp__mail__read", {}, [{"type": "text", "text": ATTACK}])
    qid = guard.log()[-1]["quarantine_id"]
    victim = tmp_path / "victim.txt"
    victim.write_text("untouched")
    folder = guard.home / "released"
    folder.mkdir(exist_ok=True)
    os.symlink(victim, folder / f"{qid}.txt")  # the notice named this path before any release
    monkeypatch.setenv("JEVGUARD_HOME", str(guard.home))
    files = store.release(config.load(), qid)[1]
    assert victim.read_text() == "untouched" and not files[0].is_symlink() and files[0].read_text() == ATTACK


# ---- #16 nothing encoded, parameterised or doubled in a trusted path ------------------------------
@pytest.mark.parametrize("url", [
    "https://docs.example.com/guide/%2e%2e/private",
    "https://docs.example.com/guide/a/%2f..%2f..%2fprivate",
    "https://docs.example.com/guide/%2E%2E%2Fprivate",
    "https://docs.example.com/guide/%252e%252e/private",
    "https://docs.example.com/guide/..%5cprivate",
    "https://docs.example.com/guide/..;/private",
    "https://docs.example.com/guide/a;x=1/../private",
    "https://docs.example.com/guide//private",
    "https://docs.example.com/guide/a%20b",
    "https://docs.example.com/guide/.../private",
])
def test_issue16_escapes_and_odd_segments_are_not_trusted(url):
    assert provenance.trusted_source(url, [PREFIX]) is False


def test_issue16_plain_paths_still_are(guard):
    for url in (PREFIX, PREFIX + "/", PREFIX + "/hooks/reference.html?x=1&y=%2F#top", PREFIX + "/a-b_c.d/e"):
        assert provenance.trusted_source(url, [PREFIX]) is True, url
    guard.configure(mode="block", on_error="closed", trusted_sources=[PREFIX])
    fetch = {"url": PREFIX + "/%2e%2e/private", "prompt": "x"}
    result = {"bytes": 1, "code": 200, "codeText": "OK", "result": ATTACK, "durationMs": 1, "url": fetch["url"]}
    assert guard.hook("PostToolUse", "WebFetch", fetch, result) is not None


# ---- #17 trust comes from what is fetched, not from what is printed -------------------------------
@pytest.mark.parametrize("command", [
    f'curl --config attacker.cfg; printf "{PREFIX}"',
    f"curl -K attacker.cfg; echo {PREFIX}",
    f"curl -Kattacker.cfg {PREFIX}/a",
    f"curl -s {PREFIX}/a; python3 fetch.py",
    f"curl -s {PREFIX}/a && ./fetch.sh",
    f'curl -s "$TARGET"; echo {PREFIX}',
    f"curl -s -x http://proxy.evil.example:3128 {PREFIX}/a",
    f"curl -s --resolve docs.example.com:443:203.0.113.9 {PREFIX}/a",
    f"curl -s --connect-to docs.example.com:443:evil.example:443 {PREFIX}/a",
    f"curl -s -H 'Host: evil.example' {PREFIX}/a",
    f"https_proxy=http://evil.example:3128 curl -s {PREFIX}/a",
    f"curl -s docs.example.com/guide/a {PREFIX}/b",
    f"wget -q -i urls.txt; echo {PREFIX}",
    f"wget -q -e https_proxy=evil.example:3128 {PREFIX}/a",
    f"curl -s {PREFIX}/a # and https://news.example.com/b",
    f"curl -sk {PREFIX}/a",                                        # no certificate check: anyone can answer
    f"./curl -s {PREFIX}/a",                                       # some other program called curl
    f"curl -s {PREFIX}/a; env -S 'curl -K attacker.cfg'",
    f"sudo -u nobody curl -s {PREFIX}/a",
    f"curl -s -H @headers.txt {PREFIX}/a",
    f"curl -s -H 'X-Forwarded-Host: evil.example' {PREFIX}/a",
    f"curl -s {PREFIX}/a | sed -e '1e id'",                        # sed can run programs
    f"curl -s {PREFIX}/a | sort --compress-program=./x",
    f"curl -s -o x" + "{,evil.example/p} " + f"{PREFIX}/a",        # the shell makes a second address of it
    f"curl -s {PREFIX}/a" + "{/.,}.{/.,}./private",                # ... or climbs out of the prefix
    f"curl -s {PREFIX}/[a-c]",
    f"curl -s {PREFIX}/a \\\n  -x http://proxy.evil.example:3128",
    f"cat <<EOF | curl -s {PREFIX}/a\nx\nEOF",
])
def test_issue17_a_fetch_whose_origin_is_not_plain_is_ordinary_outside_content(guard, command):
    guard.configure(mode="block", on_error="closed", trusted_sources=[PREFIX])
    assert run(guard, command, ATTACK) is not None, command
    assert guard.log()[-1]["mode"] == "external"


@pytest.mark.parametrize("command", [
    f"curl -s {PREFIX}/a",
    f"curl -sSL --compressed -H 'Accept: text/markdown' -o out/a.md {PREFIX}/a.md",
    f"curl -fsSL {PREFIX}/a | head -50 | grep -n hooks",
    f"wget -q -O - {PREFIX}/a | jq .",
    f"cd /tmp && curl -s {PREFIX}/a > a.html",
    f"curl -s {PREFIX}/a 2>/dev/null | sed -n '1,80p'",
    f"curl -s --proto '=https' --tlsv1.2 -w '%{{http_code}}' -H 'Accept: */*' \\\n  '{PREFIX}/a?x=1&y=2'",
    f"rtk curl -s {PREFIX}/a 2>&1 | tail -n 20",
    f"wget -nv -qO- {PREFIX}/a",
])
def test_issue17_a_plain_fetch_of_a_trusted_address_still_is(guard, command):
    guard.configure(mode="block", trusted_sources=[PREFIX])
    assert run(guard, command, ATTACK) is None, command
    assert guard.log()[-1]["mode"] == "trusted"


def test_issue17_a_settings_file_of_curl_or_wget_ends_the_exemption(guard, tmp_path):
    """Such a file can name a proxy, and nothing in the command shows it."""
    guard.configure(mode="block", on_error="closed", trusted_sources=[PREFIX])
    guard.env = {"HOME": str(tmp_path)}
    assert run(guard, f"curl -s {PREFIX}/a", ATTACK) is None
    (tmp_path / ".curlrc").write_text("proxy = http://proxy.evil.example:3128\n")
    assert run(guard, f"curl -s {PREFIX}/a", ATTACK + " again") is not None
    assert run(guard, f"wget -qO- {PREFIX}/a", ATTACK + " a third time") is None  # wget does not read it
    (tmp_path / ".wgetrc").write_text("https_proxy = http://proxy.evil.example:3128\n")
    assert run(guard, f"wget -qO- {PREFIX}/a", ATTACK + " a fourth time") is not None


def test_issue17_a_fetch_whose_address_is_in_a_config_file_is_scanned_at_all(guard, jev):
    n = len(jev.requests)
    run(guard, "curl -s --config targets.cfg", BENIGN)
    run(guard, "wget -q --input-file=urls.txt", BENIGN + " again")
    assert len(jev.requests) == n + 2 and guard.log()[-1]["mode"] == "external"


# ---- #18 a read with query fields is a read -------------------------------------------------------
@pytest.mark.parametrize("command", [
    "gh api -X GET repos/acme/widget/issues -f per_page=10",
    "gh api repos/acme/widget/issues --method GET --field per_page=10",
    "gh api repos/acme/widget/issues -f per_page=10 -X GET",
    "gh api --method=GET -F per_page=10 repos/acme/widget/issues/7/comments",
    "gh api -XGET repos/acme/widget/issues --raw-field state=all",
])
def test_issue18_a_get_with_fields_is_withheld_like_any_read(guard, command):
    guard.configure(mode="block", on_error="closed", own_repos=OWN)
    assert run(guard, command, "Issue from a stranger. " + ATTACK) is not None, command
    assert guard.log()[-1]["mode"] == "own" and guard.log()[-1]["action"] == "blocked"


@pytest.mark.parametrize("command", [
    "gh api -X POST -X GET repos/acme/widget/issues -f per_page=10",   # two methods
    "gh api -iX GET repos/acme/widget/issues",                         # options run together
    "gh api --frobnicate repos/acme/widget/issues",                    # an option this reader does not know
    "gh api -H repos/acme/widget/x graphql -f query=q",                # the endpoint is graphql, not the header value
    "gh api repos/acme/../stranger/widget/issues",
    "gh api repos/acme/widget/issues repos/acme/widget/pulls",
])
def test_issue18_a_call_that_cannot_be_read_gets_no_leniency(guard, command):
    guard.configure(mode="block", on_error="closed", own_repos=OWN)
    assert run(guard, command, "borderline-sample status line") is not None, command
    assert guard.log()[-1]["mode"] == "external"


@pytest.mark.parametrize("command", [
    "gh api -X PATCH repos/acme/widget/issues/7 -f state=closed",      # the reply is the whole issue
    "gh api repos/acme/widget/issues/7/assignees -f assignees=me",     # so is this one
    "gh api -X PUT repos/acme/widget/pulls/14/merge",
    "gh issue close 7 --repo acme/widget",                             # prints the issue's title
    "gh pr merge 14 --repo acme/widget --squash",
])
def test_issue18_a_change_to_something_that_exists_is_not_an_echo(guard, command):
    guard.configure(mode="block", on_error="closed", own_repos=OWN)
    assert run(guard, command, "Issue from a stranger. " + ATTACK) is not None, command
    assert guard.log()[-1]["mode"] == "own" and guard.log()[-1]["action"] == "blocked"


@pytest.mark.parametrize("command, writes", [
    ("gh api -X PATCH repos/acme/widget/pulls/14 -f title=x", True),
    ("gh api repos/acme/widget/issues -f title=x -f body=y", True),      # fields without a method: POST
    ("gh api --method DELETE repos/acme/widget/issues/comments/9", True),
    ("gh api repos/acme/widget/issues --input payload.json", True),
    ("gh pr create --repo acme/widget --title x --body y", True),
    ("gh issue comment 7 --repo acme/widget --body done", True),
    ("gh api repos/acme/widget/issues", False),
    ("gh api -X GET repos/acme/widget/issues -f per_page=10", False),
    ("gh api -X POST -X GET repos/acme/widget/issues -f a=b", False),     # two methods: not plainly a write
    ("gh pr view 14 --repo acme/widget --comments", False),
    ("gh issue list --repo acme/widget --search create", False),
    ("gh pr list --repo acme/widget --json title", False),
])
def test_issue18_what_counts_as_a_write(command, writes):
    assert github.gh_writes(command.split()) is writes


@pytest.mark.parametrize("command", [
    "gh api repos/acme/widget/../../stranger/widget/issues",
    "gh api repos/acme/widget/%2e%2e/%2e%2e/stranger/widget/issues",
    "gh api repos/acme/widget/issues --hostname ghe.evil.example",
    "gh issue list --repo acme/widget --hostname ghe.evil.example",
])
def test_issue18_a_path_or_host_that_leads_elsewhere_is_not_an_own_repository(command):
    assert github.gh_repos(command.split(), ["/work"]) is None


def test_curl_and_wget_startup_files_count_as_startup_files(guard):
    from jevguard import gate
    for command in ("echo 'proxy = evil.example:3128' >> ~/.curlrc", "cp evil ~/.wgetrc", "cat creds >> ~/.netrc"):
        assert gate.risky("Bash", {"command": command}), command
