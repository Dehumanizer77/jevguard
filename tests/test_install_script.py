"""install.sh: what it does before it would change anything. The part that changes the system
needs root and is not run here; what it then runs is setup-system (test_system_install.py).

Each case runs the script with its arguments as a list, no shell in between. Where a case has
to get past the check for root, a stand-in `id` that prints 0 is put first on the PATH: the
script must then stop at its own check that it lies where only root can write, before it
clones or installs anything."""

import getpass
import os
import subprocess

from conftest import ROOT

SCRIPT = str(ROOT / "install.sh")


def run(*args, env=None):
    return subprocess.run(["bash", SCRIPT, *args], capture_output=True, text=True, timeout=30,
                          env={**os.environ, **(env or {})})


def test_help_and_a_dry_run_change_nothing():
    r = run("--help")
    assert r.returncode == 0 and "--dry-run" in r.stdout
    r = run("--dry-run", "--user", getpass.getuser(), "--dir", "/nonexistent/jevguard")
    assert r.returncode == 0, r.stderr
    assert "would install jevguard for the system" in r.stdout and "agents:     claude" in r.stdout
    assert f"setup-system --user {getpass.getuser()} --agent claude" in r.stdout
    r = run("--dry-run", "--user", getpass.getuser(), "--agent", "codex")
    assert "agents:     codex\n" in r.stdout


def test_what_it_refuses_before_it_does_anything(tmp_path):
    user = getpass.getuser()
    for args, said in ((["--user", user, "--agent", "grok"], "--agent takes claude or codex"),
                       (["--user", user, "--dir", "relative/place"], "--dir takes an absolute path"),
                       (["--user", "root"], "is not root"),
                       (["--user", "no-such-user-jevguard"], "no user no-such-user-jevguard"),
                       (["--bogus"], "unknown argument")):
        r = run(*args, "--dry-run")
        assert r.returncode == 1 and said in r.stderr, (args, r.stderr)
    r = run("--user", user, "--dir", str(tmp_path / "opt"))
    assert r.returncode == 1 and "run it as root" in r.stderr
    assert not (tmp_path / "opt").exists()


def test_as_root_it_refuses_to_run_from_a_place_others_can_write(tmp_path):
    """The agent runs as the user whose home a downloaded copy would lie in, and could change it
    between the download and sudo. Here the script is the test user's: it stops before git."""
    shim = tmp_path / "bin"
    shim.mkdir()
    (shim / "id").write_text("#!/bin/sh\necho 0\n")
    (shim / "id").chmod(0o755)
    r = run("--user", getpass.getuser(), "--dir", str(tmp_path / "opt"),
            env={"PATH": f"{shim}:{os.environ['PATH']}"})
    assert r.returncode == 1 and "is not root's alone" in r.stderr, r.stderr
    assert not (tmp_path / "opt").exists() and "cloning" not in r.stdout
