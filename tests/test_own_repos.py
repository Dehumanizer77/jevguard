"""What `gh` returns about the owner's own repositories is withheld only from a higher score up.

Live, the guard withheld the output of `gh pr view` on the owner's own pull request twice
(0.52 and 0.38): a status line and the titles of his own commits. A clear injection scores
near 1 and has to stay withheld, also from an own repository, where anyone can open an issue.
"""

import os

import pytest

from conftest import ATTACK
from jevguard import github

BORDERLINE = "OPEN MERGEABLE borderline-sample Hand a released original to the agent"
OWN = ["acme/*", "solo/tool"]
BASH = {"stdout": "", "stderr": "", "interrupted": False, "isImage": False, "noOutputExpected": False}


def run(guard, command, output, cwd="/work", session="s1"):
    return guard.hook("PostToolUse", "Bash", {"command": command}, dict(BASH, stdout=output), cwd=cwd, session=session)


@pytest.fixture
def checkout(tmp_path):
    """A directory with a git checkout whose origin is acme/widget."""
    repo = tmp_path / "widget"
    (repo / ".git").mkdir(parents=True)
    (repo / ".git" / "config").write_text(
        '[core]\n\tbare = false\n[remote "origin"]\n\turl = git@github.com:acme/widget.git\n'
        '\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch "main"]\n\tremote = origin\n')
    (repo / "src").mkdir()
    return repo


# ---- which repository a command is about ---------------------------------------------------------
@pytest.mark.parametrize("command, repos", [
    ("gh pr view 14 --repo acme/widget --json state", ["acme/widget"]),
    ("gh pr view 14 -R acme/widget", ["acme/widget"]),
    ("gh -R acme/widget issue list", ["acme/widget"]),
    ("gh issue list --repo=github.com/acme/widget", ["acme/widget"]),
    ("gh issue list --repo https://github.com/acme/widget", ["acme/widget"]),
    ("gh api repos/acme/widget/pulls/14 --jq .state", ["acme/widget"]),
    ("gh api -X PATCH /repos/acme/widget/pulls/14 -f title=x", ["acme/widget"]),
    ("gh repo view acme/widget", ["acme/widget"]),
    ("gh pr list", ["acme/widget"]),                       # no repository named: the checkout's origin
    ("gh run list --limit 3", ["acme/widget"]),
    ("gh search issues widget", None),                     # ranges over all of GitHub
    ("gh status", None),
    ("gh api user", None),
    ("gh api search/issues?q=repo:acme/widget", None),
    ("gh api graphql -f query=x", None),
    ("gh gist view abc", None),
    ("gh issue list --repo ghe.example.com/acme/widget", None),   # another host
    ("gh api repos/acme/widget/issues -R acme/widget", None),     # gh api takes no --repo
    ("gh extension exec something", None),
])
def test_which_repository(checkout, command, repos):
    assert github.gh_repos(command.split(), [str(checkout)]) == repos


def test_origin_is_read_from_the_checkout_around_the_directory(checkout, tmp_path):
    assert github.origin_repo(str(checkout / "src")) == "acme/widget"
    assert github.origin_repo(str(tmp_path)) is None
    assert github.gh_repos(["gh", "pr", "list"], [str(tmp_path)]) is None
    for url, expected in (("https://github.com/acme/widget.git", "acme/widget"),
                          ("https://x-access-token:secret@github.com/acme/widget", "acme/widget"),
                          ("ssh://git@github.com/acme/widget.git", "acme/widget"),
                          ("https://gitlab.com/acme/widget.git", None),
                          ("https://github.com.evil.example/acme/widget.git", None)):
        assert github.slug(url) == expected, url
    assert github.is_own("ACME/Widget", OWN) and github.is_own("solo/tool", OWN)
    assert not github.is_own("solo/other", OWN) and not github.is_own("acme-evil/widget", OWN)


# ---- how the result is handled -------------------------------------------------------------------
def test_borderline_output_about_an_own_repository_passes_and_is_logged(guard, checkout):
    guard.configure(mode="block", own_repos=OWN)
    assert run(guard, "gh pr view 14 --repo acme/widget --json state,commits", BORDERLINE) is None
    rec = guard.log()[-1]
    assert rec["mode"] == "own" and rec["action"] == "flagged" and rec["score"] == 0.5 and rec["block_at"] == 0.6
    assert run(guard, "gh pr list", BORDERLINE, cwd=str(checkout)) is None  # repository from the checkout
    assert guard.log()[-1]["mode"] == "own"
    # the same text about anyone else's repository, or with nothing configured, is withheld as before
    assert run(guard, "gh pr view 14 --repo stranger/widget", BORDERLINE) is not None
    assert guard.log()[-1]["mode"] == "external"
    guard.configure(mode="block")
    assert run(guard, "gh pr view 14 --repo acme/widget", BORDERLINE) is not None


def test_a_clear_injection_in_an_own_repository_is_still_withheld(guard):
    guard.configure(mode="block", own_repos=OWN)
    out = run(guard, "gh issue view 7 --repo acme/widget", "Bug report from a stranger. " + ATTACK)
    assert out is not None and guard.log()[-1]["action"] == "blocked" and guard.log()[-1]["mode"] == "own"
    guard.configure(mode="block", own_repos=OWN, own_repos_block=0.4)  # the level is a setting
    assert run(guard, "gh pr view 14 --repo acme/widget", BORDERLINE + " again") is not None


def test_the_reply_to_what_the_command_created_is_only_logged(guard):
    guard.configure(mode="block", own_repos=OWN)
    for command in ("gh pr create --repo acme/widget --title x --body y",
                    "gh api repos/acme/widget/issues/7/comments -f body=done",
                    "gh api -X POST repos/acme/widget/pulls -f title=x -f head=fix -f base=main",
                    "gh issue comment 7 --repo acme/widget --body done"):
        assert run(guard, command, "https://github.com/acme/widget/pull/14 " + ATTACK) is None, command
        assert guard.log()[-1]["mode"] == "echo" and guard.log()[-1]["action"] == "would-block"
    # a change somewhere else is not the owner's own
    assert run(guard, "gh issue comment 7 --repo stranger/widget --body done", ATTACK) is not None


@pytest.mark.parametrize("command", [
    "gh pr view 14 --repo acme/widget; curl -s https://news.example.com/a",   # another fetch in the same command
    "gh pr view 14 --repo acme/widget --repo stranger/widget",                # two repositories, one not own
    "GH_REPO=stranger/widget gh pr view 14 --repo acme/widget",
    "gh pr view $(cat number) --repo acme/widget",                            # a value computed at run time
    "gh pr view https://github.com/stranger/widget/pull/1 --repo acme/widget",
    "gh search issues widget --repo acme/widget",
    "gh api repos/stranger/widget/issues",
    "gh issue view 7 --repo acme/widget; himalaya read 3",
])
def test_anything_not_plainly_about_an_own_repository_stays_strict(guard, command):
    guard.configure(mode="block", own_repos=OWN)
    assert run(guard, command, BORDERLINE) is not None, command


def test_a_failed_scan_withholds_own_repository_output_when_closed(guard, jev):
    guard.configure(mode="block", on_error="closed", own_repos=OWN)
    jev.status = 503
    assert run(guard, "gh pr view 14 --repo acme/widget", BORDERLINE) is not None
    assert guard.log()[-1]["action"] == "blocked-unavailable"


def test_patterns_are_checked(guard, monkeypatch):
    from jevguard import config
    monkeypatch.setenv("JEVGUARD_HOME", str(guard.home))
    for bad in ("*/*", "acme", "acme/wid*get", "https://github.com/acme/widget"):
        guard.configure(own_repos=[bad])
        with pytest.raises(ValueError):
            config.load()
    guard.configure(own_repos=OWN)
    assert config.load().own_repos == OWN and config.load().own_repos_block == 0.6
