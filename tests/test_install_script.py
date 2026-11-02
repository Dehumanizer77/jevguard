"""install.sh. Each case runs it with its arguments as a list, no shell in between.

The part that needs root is run through a small driver that reads the script as a library and
stands in for what only root has: am_root says yes, and where a case needs a tree to pass as
root's, root_uid is the test's user and the directories above it are not looked at. Everything
after that runs as written: git really runs in the fixtures, with stand-ins for the code it
fetches. A helper a fixture's .git names only leaves a marker file."""

import getpass
import os
import subprocess

import pytest

from conftest import ROOT

SCRIPT = str(ROOT / "install.sh")
USER = getpass.getuser()
GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "init.defaultBranch=main"]


def run(*args, env=None):
    return subprocess.run(["bash", SCRIPT, *args], capture_output=True, text=True, timeout=30,
                          env={**os.environ, **(env or {})})


def as_root(tmp_path, *args, stand_ins="", env=None):
    """main with am_root saying yes, and whatever else stand_ins sets after the script is read."""
    driver = tmp_path / "driver.sh"
    driver.write_text(f'source {SCRIPT}\nam_root() {{ :; }}\n{stand_ins}\nmain "$@"\n')
    return subprocess.run(["bash", str(driver), *args], capture_output=True, text=True, timeout=60,
                          env={**os.environ, **(env or {})})


# The tree counts as root's: the owner is the test's user, and / and /tmp above it are left out.
OWNED = 'root_uid=$(id -u)\ncheck_self() { :; }\ncheck_chain() { :; }\n'


def git(*args, cwd=None):
    subprocess.run([*GIT, *args], cwd=cwd, check=True, capture_output=True, timeout=30)


@pytest.fixture
def clone(tmp_path):
    """An origin with a stand-in for the code, and a clone of it whose fetch runs a helper that
    leaves a marker: what root would run, if .git could be written by someone else."""
    work = tmp_path / "work"
    work.mkdir()
    git("init", "-q", cwd=work)
    (work / "bin").mkdir()
    log = tmp_path / "jevguard-ran"
    (work / "bin" / "jevguard").write_text(f'#!/bin/sh\necho "$@" >> {log}\n')
    (work / "bin" / "jevguard").chmod(0o755)
    git("add", ".", cwd=work)
    git("commit", "-qm", "code", cwd=work)
    origin = tmp_path / "origin.git"
    git("clone", "-q", "--bare", str(work), str(origin))
    checkout = tmp_path / "opt"
    git("clone", "-q", str(origin), str(checkout))
    helper = tmp_path / "helper"
    marker = tmp_path / "helper-ran"
    helper.write_text(f"#!/bin/sh\ntouch {marker}\nexit 47\n")
    helper.chmod(0o755)
    git("config", "remote.origin.uploadpack", str(helper), cwd=checkout)
    return type("clone", (), {"dir": checkout, "origin": origin, "marker": marker, "log": log})()


def test_help_and_a_dry_run_change_nothing():
    r = run("--help")
    assert r.returncode == 0 and "--dry-run" in r.stdout
    r = run("--dry-run", "--user", USER, "--dir", "/nonexistent/jevguard")
    assert r.returncode == 0, r.stderr
    assert "would install jevguard for the system" in r.stdout and "agents:     claude" in r.stdout
    assert f"setup-system --user {USER} --agent claude" in r.stdout
    r = run("--dry-run", "--user", USER, "--agent", "codex")
    assert "agents:     codex\n" in r.stdout


def test_what_it_refuses_before_it_does_anything(tmp_path):
    for args, said in ((["--user", USER, "--agent", "grok"], "--agent takes claude or codex"),
                       (["--user", USER, "--dir", "relative/place"], "--dir takes an absolute path"),
                       (["--user", USER, "--ref", "--upload-pack=x"], "--ref takes a branch"),
                       (["--user", "root"], "is not root"),
                       (["--user", "no-such-user-jevguard"], "no user no-such-user-jevguard"),
                       (["--bogus"], "unknown argument")):
        r = run(*args, "--dry-run")
        assert r.returncode == 1 and said in r.stderr, (args, r.stderr)
    r = run("--user", USER, "--dir", str(tmp_path / "opt"))
    assert r.returncode == 1 and "run it as root" in r.stderr
    assert not (tmp_path / "opt").exists()


def test_as_root_it_refuses_to_run_from_a_place_others_can_write(tmp_path):
    """The agent runs as the user whose home a downloaded copy would lie in, and could change it
    between the download and sudo. Here the script is the test user's: it stops before git."""
    r = as_root(tmp_path, "--user", USER, "--dir", str(tmp_path / "opt"))
    assert r.returncode == 1 and f"{SCRIPT} is not root's alone" in r.stderr, r.stderr
    assert not (tmp_path / "opt").exists() and "cloning" not in r.stdout


def test_a_new_destination_under_a_directory_others_can_write_is_refused(tmp_path):
    """#92: --dir was not looked at. The script itself passes here; the place it would clone to
    does not, and nothing is cloned."""
    r = as_root(tmp_path, "--user", USER, "--dir", str(tmp_path / "new" / "opt"), stand_ins="check_self() { :; }")
    assert r.returncode == 1 and "is not root's alone" in r.stderr and "cloning" not in r.stdout, r.stderr


def test_the_check_of_the_directories_above_passes_what_is_roots(tmp_path):
    """With root_uid as it is: a real path of the system's passes, also through a link, and one
    in a directory others may write does not."""
    driver = tmp_path / "chain.sh"
    driver.write_text(f'source {SCRIPT}\ncheck_chain "$1"\necho passed\n')
    for path in ("/usr/bin/env", "/bin/sh", "/usr/bin/no-such-file-jevguard/deeper"):
        r = subprocess.run(["bash", str(driver), path], capture_output=True, text=True, timeout=20)
        assert r.stdout.strip() == "passed", (path, r.stderr)
    r = subprocess.run(["bash", str(driver), str(tmp_path / "x")], capture_output=True, text=True, timeout=20)
    assert r.returncode == 1 and "is not root's alone" in r.stderr


def test_the_fixture_shows_what_git_would_run(tmp_path, clone):
    """The control: with .git as it should be, git runs what the configuration names. That is
    why it has to be looked at first."""
    r = as_root(tmp_path, "--user", USER, "--dir", str(clone.dir), "--no-selftest", stand_ins=OWNED)
    assert clone.marker.exists() and r.returncode != 0


@pytest.mark.parametrize("loosen", ["config", "hooks", "new hook", "link", "worktree file"])
def test_git_does_not_run_in_a_clone_others_can_write(tmp_path, clone, loosen):
    """#92: a clone whose .git others may write. Its uploadpack, or a hook, would have run as root
    at the first fetch, before setup-system's own check of the tree refused it."""
    git_dir = clone.dir / ".git"
    if loosen == "config":
        (git_dir / "config").chmod(0o666)
    elif loosen == "hooks":
        (git_dir / "hooks").chmod(0o777)
    elif loosen == "new hook":
        (git_dir / "hooks" / "post-checkout").write_text("#!/bin/sh\n")
        (git_dir / "hooks" / "post-checkout").chmod(0o775)
    elif loosen == "link":
        (git_dir / "hooks" / "post-checkout").symlink_to(tmp_path / "elsewhere")
    else:
        (clone.dir / "bin" / "jevguard").chmod(0o777)
    r = as_root(tmp_path, "--user", USER, "--dir", str(clone.dir), "--no-selftest", stand_ins=OWNED)
    assert r.returncode == 1 and "is not root's alone" in r.stderr, r.stderr
    assert not clone.marker.exists() and "updating" not in r.stdout and not clone.log.exists()


def test_a_clone_of_another_owner_is_refused(tmp_path, clone):
    r = as_root(tmp_path, "--user", USER, "--dir", str(clone.dir), "--no-selftest",
                stand_ins=OWNED + "root_uid=$(( $(id -u) + 1 ))\n")
    assert r.returncode == 1 and "is not root's alone" in r.stderr and not clone.marker.exists()


def test_a_clone_that_takes_its_settings_from_elsewhere_is_refused(tmp_path, clone):
    (clone.dir / ".git" / "commondir").write_text(str(tmp_path / "elsewhere") + "\n")
    r = as_root(tmp_path, "--user", USER, "--dir", str(clone.dir), "--no-selftest", stand_ins=OWNED)
    assert r.returncode == 1 and "commondir" in r.stderr and not clone.marker.exists()


def test_root_takes_nothing_from_the_environment_it_was_started_in(tmp_path, clone):
    """su keeps the caller's environment, sudo may keep HOME: a git of the agent's user first on
    the PATH, or its ~/.gitconfig, would have run as root."""
    home = tmp_path / "home"
    (home / "bin").mkdir(parents=True)
    fake = tmp_path / "fake-git-ran"
    (home / "bin" / "git").write_text(f"#!/bin/sh\ntouch {fake}\n")
    (home / "bin" / "git").chmod(0o755)
    hook = tmp_path / "config-hook-ran"
    (home / ".gitconfig").write_text(f'[core]\n\tfsmonitor = "touch {hook}; false"\n')
    subprocess.run(["git", "config", "--unset", "remote.origin.uploadpack"], cwd=clone.dir, check=True)
    started = {"PATH": f"{home / 'bin'}:{os.environ['PATH']}", "HOME": str(home)}
    args = ("--user", USER, "--dir", str(clone.dir), "--no-selftest")
    r = as_root(tmp_path, *args, stand_ins=OWNED, env={**started, "GIT_CONFIG_GLOBAL": str(home / ".gitconfig"),
                                                       "GIT_DIR": str(tmp_path / "elsewhere")})
    assert r.returncode == 0, r.stderr
    assert not fake.exists() and not hook.exists()
    # The control: left as it was started, it does run them.
    as_root(tmp_path, *args, stand_ins=OWNED + "clean_environment() { :; }\n", env=started)
    assert fake.exists()
    as_root(tmp_path, *args, stand_ins=OWNED + "clean_environment() { :; }\n", env={"HOME": str(home)})
    assert hook.exists()


def test_an_update_and_a_new_clone_run_setup_from_the_checked_code(tmp_path, clone):
    """The whole way through, with a stand-in for the code: fetched, checked, and only then run."""
    subprocess.run(["git", "config", "--unset", "remote.origin.uploadpack"], cwd=clone.dir, check=True)
    r = as_root(tmp_path, "--user", USER, "--dir", str(clone.dir), "--no-selftest", "--agent", "claude", stand_ins=OWNED)
    assert r.returncode == 0, r.stderr
    assert "updating" in r.stdout and "code at" in r.stdout and "Done. Next:" in r.stdout
    assert clone.log.read_text().splitlines() == [f"setup-system --user {USER} --agent claude", "status --days 1"]
    clone.log.unlink()
    fresh = tmp_path / "fresh"
    r = as_root(tmp_path, "--user", USER, "--dir", str(fresh), "--no-selftest", "--agent", "claude",
                stand_ins=OWNED + f"repo={clone.origin}\n")
    assert r.returncode == 0, r.stderr
    assert "cloning" in r.stdout and (fresh / "bin" / "jevguard").exists()
    assert clone.log.read_text().splitlines()[0] == f"setup-system --user {USER} --agent claude"
