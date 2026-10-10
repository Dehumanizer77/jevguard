"""What `gh` returns about the owner's own repositories is withheld only from a higher score up.

Live, the guard withheld the output of `gh pr view` on the owner's own pull request twice
(0.52 and 0.38): a status line and the titles of his own commits. A clear injection scores
near 1 and has to stay withheld, also from an own repository, where anyone can open an issue.

This is a higher level, not an exemption, and it is given to one thing only: a command that is
a single `gh` invocation, written out literally, naming the repository. Earlier versions also
gave it to pipelines, to git beside gh, to a repository taken from the directory, and let the
reply to a write through unscored ("echo"). Each of those was broken through something the
shell, gh or git does that the reader had not modelled, so none of them exists any more.
"""

import pytest

from conftest import ATTACK
from jevguard import github, shell

BORDERLINE = "OPEN MERGEABLE borderline-sample Hand a released original to the agent"
OWN = ["acme/*", "solo/tool"]
BASH = {"stdout": "", "stderr": "", "interrupted": False, "isImage": False, "noOutputExpected": False}
VIEW = "gh pr view 14 --repo acme/widget"


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
    return repo


# ---- which repository a command names ------------------------------------------------------------
@pytest.mark.parametrize("command, repos", [
    ("gh pr view 14 --repo acme/widget --json state", ["acme/widget"]),
    ("gh pr view 14 -R acme/widget", ["acme/widget"]),
    ("gh pr view 14 -Racme/widget", ["acme/widget"]),
    ("gh pr view --repo acme/widget 14 --comments", ["acme/widget"]),
    ("gh pr -R acme/widget view 14", None),                # the subcommand comes first: it decides how the rest is read
    ("gh -R acme/widget issue list", None),                # not a place gh reads the option from
    ("gh issue list --repo=github.com/acme/widget", ["acme/widget"]),
    ("gh secret list --repo acme/widget", None),           # --org and --env address these elsewhere; not read
    ("gh ruleset list --repo acme/widget --org stranger", None),
    ("gh api repos/acme/widget/pulls/14 --jq .state", ["acme/widget"]),
    ("gh api -X PATCH /repos/acme/widget/pulls/14 -f title=x", ["acme/widget"]),
    ("gh repo view acme/widget", ["acme/widget"]),
    ("gh pr list", None),                                  # no repository named: not taken from the directory
    ("gh run list --limit 3", None),
    ("gh repo view", None),
    ("gh search issues widget", None),                     # ranges over all of GitHub
    ("gh status", None),
    ("gh api user", None),
    ("gh api search/issues?q=repo:acme/widget", None),
    ("gh api graphql -f query=x", None),
    ("gh gist view abc", None),
    ("gh issue list --repo ghe.example.com/acme/widget", None),   # another host
    ("gh issue list --repo acme/widget --hostname ghe.example.com", None),
    ("gh api repos/acme/widget/issues --hostname ghe.example.com", None),
    ("gh api repos/acme/widget/issues -R acme/widget", None),     # gh api takes no --repo
    ("gh api repos/acme/widget/../../stranger/widget/issues", None),
    ("gh api repos/acme/widget/%2e%2e/%2e%2e/stranger/widget/issues", None),
    ("gh api repos/acme/widget/issues repos/acme/widget/pulls", None),
    ("gh api -iX GET repos/acme/widget/issues", None),            # options run together
    ("gh api --frobnicate repos/acme/widget/issues", None),       # an option this reader does not know
    ("gh api -H repos/acme/widget/x graphql -f query=q", None),   # the endpoint is graphql, not the header value
    ("gh pr view 14 -cR stranger/widget", None),                  # the repository named in a run of short options
    ("gh extension exec something", None),
])
def test_which_repository(command, repos):
    assert github.gh_repos(command.split()) == repos
    assert github.is_own("ACME/Widget", OWN) and github.is_own("solo/tool", OWN)
    assert not github.is_own("solo/other", OWN) and not github.is_own("acme-evil/widget", OWN)


# ---- how the result is handled -------------------------------------------------------------------
def test_borderline_output_about_an_own_repository_passes_and_is_logged(guard):
    guard.configure(mode="block", own_repos=OWN)
    assert run(guard, VIEW + " --json state,commits", BORDERLINE) is None
    rec = guard.log()[-1]
    assert rec["mode"] == "own" and rec["action"] == "flagged" and rec["score"] == 0.5 and rec["block_at"] == 0.6
    # the same text about anyone else's repository, or with nothing configured, is withheld as before
    assert run(guard, "gh pr view 14 --repo stranger/widget", BORDERLINE) is not None
    assert guard.log()[-1]["mode"] == "external"
    guard.configure(mode="block")
    assert run(guard, VIEW, BORDERLINE) is not None


def test_a_clear_injection_in_an_own_repository_is_still_withheld(guard):
    guard.configure(mode="block", own_repos=OWN)
    out = run(guard, "gh issue view 7 --repo acme/widget", "Bug report from a stranger. " + ATTACK)
    assert out is not None and guard.log()[-1]["action"] == "blocked" and guard.log()[-1]["mode"] == "own"
    guard.configure(mode="block", own_repos=OWN, own_repos_block=0.4)  # the level is a setting
    assert run(guard, VIEW, BORDERLINE + " again") is not None


@pytest.mark.parametrize("command", [
    "gh pr create --repo acme/widget --title x --body y",
    "gh issue comment 7 --repo acme/widget --body done",
    "gh pr edit 14 --repo acme/widget --title x",
    "gh release create v1.0 --repo acme/widget --generate-notes",
    "gh api repos/acme/widget/issues -f title=x -f body=y",
    "gh api repos/acme/widget/pulls -F issue=7 -f head=fix -f base=main",
    "gh api -X PATCH repos/acme/widget/issues/7 -f state=closed",
    "gh issue close 7 --repo acme/widget",
])
def test_the_reply_to_a_write_is_scored_like_everything_else(guard, command):
    """There is no "echo". What comes back for a write may hold more than what was sent."""
    guard.configure(mode="block", on_error="closed", own_repos=OWN)
    assert run(guard, command, "https://github.com/acme/widget/pull/14 " + ATTACK) is not None, command
    assert guard.log()[-1]["mode"] == "own" and guard.log()[-1]["action"] == "blocked"
    assert run(guard, command, "https://github.com/acme/widget/pull/14 " + BORDERLINE) is None


@pytest.mark.parametrize("command", [
    VIEW,
    VIEW + " 2>&1",
    VIEW + " --json title,state 2>/dev/null",
    "rtk " + VIEW,
    "gh api repos/acme/widget/pulls/14 --jq '.title + \" \" + .state'",
    "gh issue list --repo acme/widget --state open --json number,title",
    'gh pr comment 14 --repo acme/widget --body "Done, thanks!"',
])
def test_one_gh_command_written_out_gets_the_higher_level(guard, command):
    guard.configure(mode="block", own_repos=OWN)
    assert run(guard, command, BORDERLINE) is None, command
    assert guard.log()[-1]["mode"] == "own"


@pytest.mark.parametrize("command", [
    VIEW + " | head -20",                                   # one program, nothing beside it
    VIEW + " | jq .",
    VIEW + "; echo done",
    VIEW + " && echo done",
    "cd /work && " + VIEW,
    "git push -u origin fix && gh pr create --repo acme/widget --title x --body y",
    "git status; " + VIEW,
    VIEW + "; curl -s https://news.example.com/a",
    VIEW + "; curl --config attacker.cfg",
    VIEW + "; cat notes.txt",
    VIEW + " > out.txt",                                    # no redirection but of its own errors
    VIEW + " 2> errors.txt",
    VIEW + " < notes.txt",
    VIEW + " < /dev/tcp/untrusted.example/9000",
    VIEW + " &",
    "(" + VIEW + ")",
    VIEW + " # --repo stranger/widget",
    VIEW + "\ncurl -K attacker.cfg",
    "gh pr view $(cat number) --repo acme/widget",          # a value the shell still has to fill in
    "gh pr view $PR --repo acme/widget",
    'gh pr view 14 --repo "$REPO"',
    "gh pr view 14 --repo acme/widget --json titl?",        # a glob
    "gh pr view 14 --repo acme/{widget,other}",
    "gh pr view 14 --repo acme/widget --jq .[0]",
    "gh pr view ~ --repo acme/widget",
    "gh pr view 14 --repo acme/widget \\; id",
    "GH_REPO=stranger/widget " + VIEW,
    "env GH_HOST=ghe.evil.example " + VIEW,
    "sudo " + VIEW,
    VIEW + " --repo stranger/widget",                       # two repositories, one not own
    "gh pr view https://github.com/stranger/widget/pull/1 --repo acme/widget",
    "gh pr view http://ghe.internal/stranger/widget/pull/1 --repo acme/widget",
    "gh search issues widget --repo acme/widget",
    "gh api repos/stranger/widget/issues",
    "gh api graphql -f query=x",
])
def test_anything_else_is_ordinary_outside_content(guard, command):
    guard.configure(mode="block", on_error="closed", scan_local=True, own_repos=OWN)
    assert run(guard, command, BORDERLINE) is not None, command
    assert guard.log()[-1]["mode"] == "external"


def test_some_other_program_called_gh_is_not_gh(guard):
    guard.configure(mode="block", scan_local=True, own_repos=OWN)
    for n, command in enumerate(("/tmp/gh pr view 14 --repo acme/widget", "./gh pr view 14 --repo acme/widget")):
        assert run(guard, command, f"{n} {ATTACK}") is not None
        assert guard.log()[-1]["mode"] == "local"  # like any program the guard does not know


def test_the_repository_is_not_taken_from_the_directory(guard, checkout):
    """Which one gh picks there depends on the remotes and settings of the checkout."""
    guard.configure(mode="block", own_repos=OWN)
    for command in ("gh pr list", "gh pr view 14", "gh run list --limit 3"):
        assert run(guard, command, BORDERLINE, cwd=str(checkout)) is not None, command
        assert guard.log()[-1]["mode"] == "external"
    assert run(guard, "gh pr list --repo acme/widget", BORDERLINE, cwd=str(checkout)) is None


def test_gh_pointed_somewhere_else_gets_nothing(guard, tmp_path):
    guard.configure(mode="block", own_repos=OWN)
    guard.env = {"GH_CONFIG_DIR": str(tmp_path)}
    (tmp_path / "config.yml").write_text("git_protocol: https\nhttp_unix_socket:\nprompt: enabled\n")
    assert run(guard, VIEW, BORDERLINE) is None and guard.log()[-1]["mode"] == "own"
    (tmp_path / "config.yml").write_text("git_protocol: https\nhttp_unix_socket: /tmp/elsewhere.sock\n")
    assert run(guard, VIEW, BORDERLINE + " again") is not None and guard.log()[-1]["mode"] == "external"
    for n, env in enumerate(({"GH_HOST": "ghe.evil.example"}, {"GH_REPO": "stranger/widget"},
                             {"PATH": ".:/usr/bin:/bin"}, {"PATH": "/usr/bin::/bin"})):
        guard.env = {"GH_CONFIG_DIR": str(tmp_path / "none"), **env}
        assert run(guard, VIEW, f"{BORDERLINE} {n}") is not None, env
        assert guard.log()[-1]["mode"] == "external"


@pytest.mark.parametrize("command", [
    "gh api repos/acme/widget/issues --input payload.json",           # the reply holds what was in that file
    "gh api repos/acme/widget/issues -f title=x -F body=@notes.md",
    "gh api repos/acme/widget/issues/7/comments -Fbody=@notes.md",
])
def test_a_reply_that_carries_a_file_back_never_gets_the_more_lenient_level(guard, command):
    """What gh prints can hold local content. Where local output is scanned, own-repository
    output is withheld from whichever of the two levels is lower, for every gh command."""
    guard.configure(mode="block", own_repos=OWN)
    assert run(guard, command, BORDERLINE) is None and guard.log()[-1]["mode"] == "own"
    for n, also in enumerate((command, VIEW, "gh pr create --repo acme/widget --fill --dry-run")):
        guard.configure(mode="block", own_repos=OWN, scan_local=True, local_block=0.4)
        assert run(guard, also, f"{BORDERLINE} again {n}") is not None, also
        assert guard.log()[-1]["mode"] == "own" and guard.log()[-1]["block_at"] == 0.4
    guard.configure(mode="block", own_repos=OWN, scan_local=True, local_block=0.9)
    assert run(guard, command, BORDERLINE + " once more") is None and guard.log()[-1]["block_at"] == 0.6


def test_a_failed_scan_withholds_own_repository_output_when_closed(guard, jev):
    guard.configure(mode="block", on_error="closed", own_repos=OWN)
    jev.status = 503
    assert run(guard, VIEW, BORDERLINE) is not None
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


# ---- the reading everything lenient rests on -----------------------------------------------------
@pytest.mark.parametrize("line, words", [
    ("gh pr view 14 --repo acme/widget", ["gh", "pr", "view", "14", "--repo", "acme/widget"]),
    ("  gh  pr   view 14  ", ["gh", "pr", "view", "14"]),
    ("gh x 'a b' \"c!d\" e''f", ["gh", "x", "a b", "c!d", "ef"]),
    ("gh x '$HOME * ? ; | > {a,b}'", ["gh", "x", "$HOME * ? ; | > {a,b}"]),
    ("gh x 2>&1", ["gh", "x"]),
    ("gh x 2>/dev/null", ["gh", "x"]),
    ("make V=1 a@b %.o k+1 x,y", ["make", "V=1", "a@b", "%.o", "k+1", "x,y"]),
])
def test_a_line_that_is_one_program_with_literal_arguments(line, words):
    assert shell.literal_command(line) == words


@pytest.mark.parametrize("line", [
    "", "   ", "a; b", "a && b", "a || b", "a | b", "a & b", "a &", "(a)", "a > f", "a >> f", "a < f", "a 2> f",
    "a 2>&1 2>/dev/null", "a 2>&1 b", "a >&2", "a <<< x", "a <<EOF", "a $x", "a ${x}", "a $(b)", "a `b`", 'a "$x"',
    'a "`b`"', 'a "x\\"y"', "a \\; b", "a\\ b", "a *", "a ?", "a [x]", "a {x,y}", "a ~", "a ~/x", "a #x", "a !x",
    "a ^x", "a =x", "a 'x", 'a "x', "a\tb", "a\nb", "a\rb", "a\x00b", "a 'x\ny'", "a x=y\\",
])
def test_a_line_that_is_anything_more_is_not_read(line):
    assert shell.literal_command(line) is None, repr(line)
