"""A system installation (system.py, service.py): the hook asks the service for everything that
needs the API key or the guard's state, and the agents' system settings hold the hooks.

The service runs here in the test process, on a socket in tmp_path, with its own settings
directory (with the key) and state directory. The hook runs as Claude Code runs it, in a process
of its own, set up as a system installation whose settings directory has no key and whose state
directory cannot be written: whatever it scores, seals or records, the service has to do.
Nothing here needs root, and nothing here runs a command a test case names."""

import json
import os
import socket
import subprocess
import sys
import threading
import tomllib
from pathlib import Path

import pytest

from conftest import ATTACK, BENIGN, ROOT
from jevguard import config, gate, service, store, system

# The hook process: the system installation is the one in the test's directories.
_DRIVER = """
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from jevguard import system
where = json.loads(sys.argv[2])
system.settings = lambda: {"code": sys.argv[1], "users": [where["uid"]], "agents": ["claude"]}
system.CONFIG_DIR, system.STATE_DIR, system.RELEASED_DIR = Path(where["config"]), Path(where["state"]), Path(where["released"])
system.SOCKET = where["socket"]
from jevguard.hook import main
sys.argv = [sys.argv[0], *where["argv"]]
main()
"""


class SystemGuard:
    def __init__(self, tmp: Path, url: str):
        self.tmp = tmp
        self.service_config, self.state, self.released = tmp / "service-config", tmp / "state", tmp / "released"
        self.hook_config = tmp / "hook-config"  # what the hook reads: the same settings, without the key
        closed = tmp / "closed"
        closed.mkdir(mode=0o500)
        self.hook_state = closed / "state"      # the hook may not write here, nor anywhere it is not given
        for d in (self.service_config, self.state, self.released, self.hook_config):
            d.mkdir()
        (self.service_config / "typesafe.key").write_text("test-key\n")
        self.socket = str(tmp / "hook.sock")
        self.url = url
        self.configure()
        self.allowed = {os.getuid()}
        self.server = None

    def configure(self, **settings):
        self.settings = {"url": self.url, "timeout": 2.0, "deadline": 6.0, "track_missing_files": True, **settings}
        for d in (self.service_config, self.hook_config):
            (d / "config.json").write_text(json.dumps(self.settings))

    def service_cfg(self):
        cfg = config._load(self.service_config, self.state, None)
        cfg.released_dir, cfg.system = self.released, {"code": str(ROOT)}
        return cfg

    def start(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(self.socket)
        sock.listen()
        self.server = service.Server(sock, self.service_cfg, lambda: self.allowed)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None

    def hook(self, event, tool, tool_input, tool_response=None, session="s1", argv=("--agent", "claude")):
        payload = {"hook_event_name": event, "tool_name": tool, "tool_input": tool_input, "session_id": session,
                   "cwd": "/work", "tool_use_id": "toolu_test"}
        if tool_response is not None:
            payload["tool_response"] = tool_response
        where = {"uid": os.getuid(), "config": str(self.hook_config), "state": str(self.hook_state),
                 "released": str(self.released), "socket": self.socket, "argv": list(argv)}
        env = {k: v for k, v in os.environ.items() if k != "JEVGUARD_HOME"}
        r = subprocess.run([sys.executable, "-IS", "-c", _DRIVER, str(ROOT), json.dumps(where)], input=json.dumps(payload),
                           text=True, capture_output=True, timeout=60, env=env)
        assert r.returncode == 0, r.stderr
        return json.loads(r.stdout) if r.stdout.strip() else None

    def log(self):
        p = self.state / "scans.jsonl"
        return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []


@pytest.fixture
def sysguard(tmp_path, jev):
    g = SystemGuard(tmp_path, jev.url).start()
    yield g
    g.stop()


def _fetch(g, text):
    return g.hook("PostToolUse", "WebFetch", {"url": "https://example.com/x", "prompt": "summarise"}, text)


def test_the_hook_has_the_service_score_seal_and_record(sysguard):
    sysguard.configure(mode="block")
    out = _fetch(sysguard, ATTACK)
    notice = json.loads(out["hookSpecificOutput"]["updatedToolOutput"])
    assert notice["firewall"] == "blocked" and notice["quarantine_id"]
    assert len(notice["seal"]) == 32                                     # sealed with the service's key
    assert (sysguard.state / "seal.key").exists() and (sysguard.state / "quarantine" / f"{notice['quarantine_id']}.json").exists()
    assert str(sysguard.released) in notice["if_released"]
    assert _fetch(sysguard, BENIGN) is None
    assert [r["action"] for r in sysguard.log() if r.get("event") == "scan"] == ["blocked", "passed"]
    assert json.loads((sysguard.state / "usage.json").read_text())["scans"] == 2
    assert not sysguard.hook_state.exists()                               # the hook wrote nothing of its own


def test_without_the_service_the_hook_does_what_on_error_says(sysguard):
    sysguard.configure(mode="block")
    sysguard.stop()
    os.unlink(sysguard.socket)
    assert _fetch(sysguard, ATTACK) is None                               # on_error open: passed unscanned
    sysguard.configure(mode="block", on_error="closed")
    out = _fetch(sysguard, ATTACK)
    assert json.loads(out["hookSpecificOutput"]["updatedToolOutput"])["verdict"] == "unavailable"


def test_the_service_answers_only_the_owners(sysguard):
    sysguard.configure(mode="block", on_error="closed")
    sysguard.allowed = {os.getuid() + 1}
    out = _fetch(sysguard, ATTACK)
    assert json.loads(out["hookSpecificOutput"]["updatedToolOutput"])["verdict"] == "unavailable"
    with pytest.raises(service.ServiceError, match="not an owner"):
        service.Client(sysguard.socket).call("usage")


def test_the_service_does_not_release_discard_or_change_settings(sysguard):
    client = service.Client(sysguard.socket)
    for name in ("release", "discard", "released_ids", "load", "mode", "_write", "usage_add"):
        with pytest.raises(service.ServiceError, match="does not answer"):
            client.call(name, "fw-20261030-abcdef")
    assert client.call("judged", "s1", "ls", mark=True, output="x") is True
    assert client.call("judged", "s1", "ls", output="x") is True and client.call("judged", "s1", "ls", output="x") is False
    assert client.call("released") == []


def test_no_other_process_can_switch_scanning_off_through_the_service(sysguard):
    """Any process of the owner can reach the socket, so the service takes only what a hook would
    give it. It counts the tokens of its own scans: a call that spent the day's budget, or set the
    pause after a failure, would stop every scan. It prunes sessions at its own age: one of 0
    days would wipe what each session saw. And it keeps a withheld result only with the digest of
    its text: one of other content would be released, unseen, by the owner's release."""
    client = service.Client(sysguard.socket)
    sysguard.configure(mode="block")
    _fetch(sysguard, BENIGN)
    assert json.loads((sysguard.state / "usage.json").read_text())["scans"] == 1
    client.call("session_update", "s2", paths=["/work/downloaded.html"], external=True)
    client.call("prune_sessions", days=0)
    assert client.call("session", "s2")["paths"] == ["/work/downloaded.html"]
    digest = store.content_hash("the text", [b"img"])
    with pytest.raises(service.ServiceError, match="digest of that text"):
        client.call("quarantine", "WebFetch", {}, "raw", {"verdict": "injection"}, store.content_hash("other", []),
                    "the text", [b"img"])
    with pytest.raises(service.ServiceError, match="digest of that text"):
        client.call("quarantine", "WebFetch", {}, "raw", {"verdict": "injection"}, digest)
    qid = client.call("quarantine", "WebFetch", {}, "raw", {"verdict": "injection"}, digest, "the text", [b"img"])
    assert json.loads((sysguard.state / "quarantine" / f"{qid}.json").read_text())["content_sha256"] == digest


def test_bytes_go_to_the_service_and_back():
    value = {"a": [b"\x89PNG\x00", "t", {"b": b""}], "\0bytes": "not bytes, a key"}
    assert service._unpack(json.loads(json.dumps(service._pack(value)))) == value


def test_a_hook_store_read_the_service_cannot_answer_gives_the_stricter_answer(tmp_path):
    cfg = config._load(tmp_path / "c", tmp_path / "s", {"code": str(ROOT)})
    cfg.service = service.Client(str(tmp_path / "no.sock"))
    assert store.released(cfg) == frozenset() and store.judged(cfg, "s", "ls") is False
    assert store.released_artifact(cfg, "/x") is False and store.usage(cfg) == {}
    with pytest.raises(OSError):
        store.session(cfg, "s1")
    with pytest.raises(OSError):
        store.audit(cfg, event="scan")


def test_a_system_installation_takes_nothing_from_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("JEVGUARD_HOME", str(tmp_path / "elsewhere"))
    monkeypatch.setattr(system, "settings", lambda: {"code": str(ROOT), "users": [os.getuid()]})
    monkeypatch.setattr(system, "CONFIG_DIR", tmp_path / "etc")
    cfg = config.load()
    assert cfg.config_dir == tmp_path / "etc" and cfg.state_dir == system.STATE_DIR
    assert cfg.key_file == str(tmp_path / "etc" / "typesafe.key") and cfg.released_dir == system.RELEASED_DIR
    assert isinstance(cfg.service, service.Client)
    assert config.root() == (tmp_path / "etc", system.STATE_DIR)


def test_a_system_file_that_is_not_roots_alone_is_no_installation(tmp_path, monkeypatch):
    f = tmp_path / "system.json"
    f.write_text(json.dumps({"code": str(ROOT), "users": [os.getuid()]}))
    monkeypatch.setattr(system, "SYSTEM_FILE", f)
    assert system.settings() is None                                      # the test's user, not root, owns it


def test_claude_codes_managed_settings_get_the_hooks_and_keep_the_rest():
    cfg = type("cfg", (), {"mode": "block", "gate": "log", "protect_guard": True})()
    current = {"permissions": {"deny": ["Read(//secret/**)"]}, "env": {"FOO": "1"},
               "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "rtk hook claude"}]},
                                        {"matcher": "Bash", "hooks": [{"type": "command",
                                                                       "command": "/old/place/bin/jevguard-hook"}]}]}}
    wanted = system.claude_settings(cfg, current)
    assert wanted["permissions"] == current["permissions"] and wanted["env"]["FOO"] == "1"
    assert wanted["env"]["CLAUDE_CODE_SHELL_PREFIX"] == f"{system.CODE_ROOT}/bin/jevguard-shell"
    commands = [h["command"] for g in wanted["hooks"]["PreToolUse"] for h in g["hooks"]]
    assert "rtk hook claude" in commands and "/old/place/bin/jevguard-hook" not in commands
    assert system.hook_command("claude") in commands
    for event in ("PostToolUse", "PostToolUseFailure"):
        assert all(h["command"] == system.hook_command("claude") and "async" not in h
                   for g in wanted["hooks"][event] for h in g["hooks"])
    log_mode = system.claude_settings(type("cfg", (), {"mode": "log", "gate": "log", "protect_guard": True})(), wanted)
    assert "CLAUDE_CODE_SHELL_PREFIX" not in log_mode["env"]
    assert all(h.get("async") for g in log_mode["hooks"]["PostToolUse"] for h in g["hooks"])
    removed = system.claude_settings(cfg, wanted, remove=True)
    assert removed == {"permissions": current["permissions"], "env": {"FOO": "1"},
                       "hooks": {"PreToolUse": [current["hooks"]["PreToolUse"][0]]}}


def test_codex_requirements_pin_the_hooks_on():
    text = system.codex_requirements()
    req = tomllib.loads(text)
    assert text.startswith(system._OURS) and req["features"]["hooks"] is True
    assert req["hooks"]["managed_dir"] == f"{system.CODE_ROOT}/bin"
    for event in ("PreToolUse", "PostToolUse"):
        assert req["hooks"][event][0]["hooks"][0]["command"] == system.hook_command("codex")


def test_the_owners_own_hooks_are_taken_out_and_others_kept(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".codex").mkdir()
    ours = {"type": "command", "command": "/home/x/.local/share/jevguard/bin/jevguard-hook"}
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({
        "env": {"CLAUDE_CODE_SHELL_PREFIX": "/home/x/.local/share/jevguard/bin/jevguard-shell", "A": "b"},
        "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "rtk hook claude"}, ours]}],
                  "PostToolUse": [{"matcher": "Read", "hooks": [ours]}]}}))
    (tmp_path / ".codex" / "hooks.json").write_text(json.dumps({"hooks": {"PreToolUse": [{"hooks": [
        {"type": "command", "command": "/home/x/.local/share/jevguard/bin/jevguard-hook --agent codex"}]}]}}))
    done = system._remove_user_hooks(["claude", "codex"])
    assert len(done) == 2
    claude = json.loads((tmp_path / ".claude" / "settings.json").read_text())
    assert claude == {"env": {"A": "b"}, "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
        {"type": "command", "command": "rtk hook claude"}]}]}}
    assert json.loads((tmp_path / ".codex" / "hooks.json").read_text()) == {}
    assert system._remove_user_hooks(["claude", "codex"]) == []


def test_the_owners_installation_is_read_without_following_a_link(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    cfg_dir = tmp_path / ".config" / "jevguard"
    state = tmp_path / ".local" / "state" / "jevguard"
    (state / "quarantine").mkdir(parents=True)
    cfg_dir.mkdir(parents=True)
    secret = tmp_path / "not-the-key"
    secret.write_text("something else\n")
    (cfg_dir / "typesafe.key").symlink_to(secret)
    (cfg_dir / "config.json").write_text('{"mode": "block"}')
    (state / "quarantine" / "fw-20261030-abcdef.json").write_text("{}")
    (state / "quarantine" / "other.json").write_text("{}")
    found = system._read_user_installation()
    assert found["key"] is None and found["config"] and list(found["quarantine"]) == ["fw-20261030-abcdef.json"]


def test_setup_brings_the_owners_installation_over_and_replaces_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "chown", lambda *a: None)                      # root's to own; the test is not root
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    cfg_dir = tmp_path / "home" / ".config" / "jevguard"
    state = tmp_path / "home" / ".local" / "state" / "jevguard"
    released = tmp_path / "home" / ".local" / "state" / "jevguard-released"
    for d in (cfg_dir, state / "quarantine", released):
        d.mkdir(parents=True)
    (cfg_dir / "config.json").write_text('{"mode": "block", "key_file": "/elsewhere", "own_repos": ["a/*"]}')
    (cfg_dir / "typesafe.key").write_text("tsk-0123456789abcdef\n")
    (state / "seal.key").write_bytes(b"s" * 32)
    (state / "released.txt").write_text("abc fw-20261030-abcdef WebFetch released 2026-10-30\n")
    (state / "quarantine" / "fw-20261030-abcdef.json").write_text('{"tool": "WebFetch"}')
    (released / "fw-20261030-abcdef.txt").write_text("the original")
    for name, path in (("CONFIG_DIR", "etc"), ("STATE_DIR", "var"), ("RELEASED_DIR", "var-released")):
        monkeypatch.setattr(system, name, tmp_path / path)
        (tmp_path / path).mkdir()
    said = []
    system._bring_over(system._read_user_installation(), os.getuid(), os.getgid(), said.append)
    assert json.loads((tmp_path / "etc" / "config.json").read_text()) == {"mode": "block", "own_repos": ["a/*"]}
    key = tmp_path / "etc" / "typesafe.key"
    assert key.read_text() == "tsk-0123456789abcdef\n" and oct(key.stat().st_mode & 0o777) == "0o640"
    assert (tmp_path / "var" / "seal.key").read_bytes() == b"s" * 32
    assert (tmp_path / "var" / "quarantine" / "fw-20261030-abcdef.json").exists()
    copy = tmp_path / "var-released" / "fw-20261030-abcdef.txt"
    assert copy.read_text() == "the original" and oct(copy.stat().st_mode & 0o777) == "0o644"
    (cfg_dir / "typesafe.key").write_text("tsk-another-one-0000\n")
    system._bring_over(system._read_user_installation(), os.getuid(), os.getgid(), said.append)
    assert key.read_text() == "tsk-0123456789abcdef\n"                    # what is there stays
    key.unlink()
    (cfg_dir / "typesafe.key").write_text("not a key at all, with spaces\n")
    with pytest.raises(ValueError, match="does not look like an API key"):
        system._bring_over(system._read_user_installation(), os.getuid(), os.getgid(), said.append)


def test_setup_writes_the_agents_system_settings(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "chown", lambda *a: None)                      # root's to own; the test is not root
    monkeypatch.setattr(system, "CLAUDE_MANAGED", tmp_path / "claude-code" / "managed-settings.json")
    monkeypatch.setattr(system, "CODEX_REQUIREMENTS", tmp_path / "codex" / "requirements.toml")
    cfg = type("cfg", (), {"mode": "block", "gate": "log", "protect_guard": True})()
    said = []
    system.update_agents(cfg, ["claude", "codex"], said.append)
    managed = json.loads(system.CLAUDE_MANAGED.read_text())
    assert managed["env"]["CLAUDE_CODE_SHELL_PREFIX"].endswith("/bin/jevguard-shell")
    assert oct(system.CLAUDE_MANAGED.stat().st_mode & 0o777) == "0o644"
    assert system.CODEX_REQUIREMENTS.read_text() == system.codex_requirements()
    said.clear()
    system.update_agents(cfg, ["claude", "codex"], said.append)
    assert said == []                                                     # nothing to change
    system.CODEX_REQUIREMENTS.write_text("[features]\nhooks = false\n")
    system.update_agents(cfg, ["codex"], said.append)
    assert system.CODEX_REQUIREMENTS.read_text() == "[features]\nhooks = false\n" and "not written by jevguard" in said[0]


def test_the_owners_commands_need_root_in_a_system_installation(monkeypatch, capsys):
    if os.geteuid() == 0:
        pytest.skip("run as root")
    from jevguard import cli
    monkeypatch.setattr(system, "settings", lambda: {"code": str(ROOT), "users": [os.getuid()]})
    for argv in (["status"], ["mode", "log"], ["release", "fw-20261030-abcdef"], ["install"]):
        assert cli.main(argv) == 1, argv
        assert "sudo jevguard" in capsys.readouterr().err
    assert cli.main(["setup-system", "--user", "nobody"]) == 1                # and so does setup


def test_the_system_settings_are_the_guards_to_protect():
    cfg = config._load(Path("/nonexistent/c"), Path("/nonexistent/s"), None)
    for tool, inp in (("Write", {"file_path": "/etc/claude-code/managed-settings.json", "content": "{}"}),
                      ("Edit", {"file_path": "/etc/codex/requirements.toml", "old_string": "a", "new_string": "b"}),
                      ("Bash", {"command": "tee /etc/jevguard/config.json < x"}),
                      ("Bash", {"command": "touch /etc/claude-code/managed-settings.d/50-x.json"}),
                      ("Bash", {"command": "cp x /etc/systemd/system/jevguard.service"})):
        assert gate.guard_change(tool, inp, cfg, cwd="/work"), inp
    for command in ("cat /etc/claude-code/managed-settings.json", "ls /etc/codex", "touch /etc/codex-notes"):
        assert gate.guard_change("Bash", {"command": command}, cfg, cwd="/work") == "", command


def test_the_shell_prefix_takes_only_a_shell_of_the_systems(tmp_path):
    fake = tmp_path / "bin" / "bash"
    fake.parent.mkdir()
    marker = tmp_path / "ran"
    fake.write_text(f"#!/bin/sh\ntouch {marker}\n")
    fake.chmod(0o755)
    r = subprocess.run([str(ROOT / "bin" / "jevguard-shell"), "echo from-the-hook"], capture_output=True, text=True,
                       env={**os.environ, "SHELL": str(fake)}, timeout=20)
    assert r.stdout.strip() == "from-the-hook" and not marker.exists()


def test_the_units_run_the_service_as_its_user_on_its_socket():
    units = system.units()
    assert f"ListenStream={system.SOCKET}" in units["jevguard.socket"] and "SocketMode=0666" in units["jevguard.socket"]
    service_unit = units["jevguard.service"]
    assert f"User={system.USER}" in service_unit and "ProtectHome=yes" in service_unit
    assert f"ExecStart=/usr/bin/python3 -IS {system.CODE_ROOT}/bin/jevguard-service" in service_unit
    assert f"ReadWritePaths={system.STATE_DIR} {system.RELEASED_DIR}" in service_unit


def test_the_code_check_looks_at_every_directory_and_file_in_the_tree(tmp_path):
    """#88: the directories bin and jevguard themselves were not looked at, and a directory others
    may write lets them replace the root-owned files in it. Here the tree is the test user's, and
    the check is for that user (owner=); the directories above tmp_path are reported either way."""
    code = tmp_path / "code"
    for d in ("bin", "jevguard/agents", ".git/hooks"):
        (code / d).mkdir(parents=True)
    for f in ("bin/jevguard-hook", "jevguard/__init__.py", "jevguard/agents/claude.py", ".git/HEAD", "README.md"):
        (code / f).write_text("x")
    for p in [code, *code.rglob("*")]:
        p.chmod(0o755 if p.is_dir() else 0o644)
    above = system.check_code(code, owner=os.getuid())
    assert not any(str(code) in f for f in above)
    for loose in ("bin", "jevguard", "jevguard/agents", ".git/hooks", "README.md"):
        (code / loose).chmod(0o777)
        assert [f for f in system.check_code(code, owner=os.getuid()) if f not in above] == \
            [f"{code / loose} is not root's alone (owner {os.getuid()}, mode 0o777)"], loose
        (code / loose).chmod(0o755 if (code / loose).is_dir() else 0o644)
    (code / "jevguard" / "agents" / "grok.py").symlink_to("/tmp/elsewhere.py")
    assert [f for f in system.check_code(code, owner=os.getuid()) if f not in above] == \
        [f"{code / 'jevguard' / 'agents' / 'grok.py'} is a symbolic link"]
    assert any("not root's alone" in f for f in system.check_code(code))      # and for root, the test's user is not root


@pytest.fixture
def setup_env(tmp_path, monkeypatch):
    """setup() as root would run it, in tmp_path: root, systemd, the accounts and the owner's
    child process stood in for. What the agents would find when the owner runs them: works."""
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    (home / ".codex").mkdir()
    monkeypatch.setenv("HOME", str(home))
    for name, path in (("CONFIG_DIR", "etc/jevguard"), ("STATE_DIR", "var/lib/jevguard"),
                       ("RELEASED_DIR", "var/lib/jevguard-released"), ("UNITS", "etc/systemd/system"),
                       ("CLAUDE_MANAGED", "etc/claude-code/managed-settings.json"),
                       ("CODEX_REQUIREMENTS", "etc/codex/requirements.toml"), ("COMMAND_LINK", "usr/local/bin/jevguard"),
                       ("SYSTEM_FILE", "etc/jevguard/system.json")):
        monkeypatch.setattr(system, name, tmp_path / path)
    for d in ("etc/systemd/system", "usr/local/bin"):
        (tmp_path / d).mkdir(parents=True)
    monkeypatch.setattr(system, "settings", lambda: json.loads(system.SYSTEM_FILE.read_text()))
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "chown", lambda *a: None)
    monkeypatch.setattr(system, "check_code", lambda *a, **k: [])
    owner = type("pw", (), {"pw_uid": 1000, "pw_gid": 1000, "pw_name": "owner", "pw_dir": str(home)})()
    service_user = type("pw", (), {"pw_uid": 999, "pw_gid": 999})()
    monkeypatch.setattr(system.pwd, "getpwnam", lambda name: service_user if name == system.USER else owner)
    monkeypatch.setattr(system.grp, "getgrnam", lambda name: None)
    ran = []
    monkeypatch.setattr(system.subprocess, "run", lambda argv, **k: ran.append(argv))
    monkeypatch.setattr(system, "_as_owner", lambda pw, fn, *args: fn(*args))
    works = {}
    monkeypatch.setattr(system, "_works_for_owner", lambda agents: {a: works.get(a, "") for a in agents})
    return type("env", (), {"home": home, "ran": ran, "works": works})()


_OLD = "/home/owner/.local/share/jevguard/bin/jevguard-hook"


def _user_hooks(home):
    (home / ".claude" / "settings.json").write_text(json.dumps({
        "env": {"CLAUDE_CODE_SHELL_PREFIX": "/home/owner/.local/share/jevguard/bin/jevguard-shell"},
        "hooks": {"PostToolUse": [{"matcher": "Read", "hooks": [{"type": "command", "command": _OLD}]}],
                  "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "rtk hook claude"}]}]}}))
    (home / ".codex" / "hooks.json").write_text(json.dumps({"hooks": {"PostToolUse": [{"hooks": [
        {"type": "command", "command": f"{_OLD} --agent codex"}]}]}}))


def _commands(path):
    return json.dumps(json.loads(path.read_text()))


def test_setup_takes_out_only_the_selected_agents_own_hooks(setup_env, capsys):
    """#89: setup took the owner's hooks out of both Claude Code's and Codex's settings, whichever
    agents it was set up for. Set up for Claude Code, Codex keeps its own."""
    _user_hooks(setup_env.home)
    assert system.setup("owner", ["claude"]) == 0
    assert _OLD not in _commands(setup_env.home / ".claude" / "settings.json")
    assert "rtk hook claude" in _commands(setup_env.home / ".claude" / "settings.json")
    assert f"{_OLD} --agent codex" in _commands(setup_env.home / ".codex" / "hooks.json")
    assert not system.CODEX_REQUIREMENTS.exists()
    assert system.holds_hooks("claude", config.load()) == ""
    assert "rm -r" not in capsys.readouterr().out                         # no old copies to name here


def test_setup_keeps_codexs_own_hooks_when_its_requirements_are_someone_elses(setup_env, capsys):
    """#89: an administrator's requirements.toml is left alone, and then Codex's own hooks stay,
    and setup says the installation is not complete."""
    _user_hooks(setup_env.home)
    system.CODEX_REQUIREMENTS.parent.mkdir(parents=True)
    system.CODEX_REQUIREMENTS.write_text("[features]\nhooks = true\n")
    assert system.setup("owner", ["codex"]) == 1
    out = capsys.readouterr().out
    assert "NOT DONE for codex" in out and "not complete" in out
    assert f"{_OLD} --agent codex" in _commands(setup_env.home / ".codex" / "hooks.json")
    assert _OLD in _commands(setup_env.home / ".claude" / "settings.json")  # not selected: untouched
    assert system.CODEX_REQUIREMENTS.read_text() == "[features]\nhooks = true\n"


def test_setup_keeps_the_owners_hooks_when_the_guard_does_not_work_for_the_owner(setup_env, capsys):
    """The system settings may hold the hooks and still the guard not work as the agent runs it:
    the service not answering, no key, the hook failing. Then nothing is taken out."""
    _user_hooks(setup_env.home)
    setup_env.works["claude"] = "the service does not answer the owner: [Errno 111] Connection refused"
    setup_env.works["codex"] = "no API key"
    assert system.setup("owner", ["claude", "codex"]) == 1
    out = capsys.readouterr().out
    assert "NOT DONE for claude: the service does not answer" in out and "NOT DONE for codex: no API key" in out
    assert _OLD in _commands(setup_env.home / ".claude" / "settings.json")
    assert "jevguard-shell" in _commands(setup_env.home / ".claude" / "settings.json")
    assert f"{_OLD} --agent codex" in _commands(setup_env.home / ".codex" / "hooks.json")
    setup_env.works.clear()
    assert system.setup("owner", ["claude", "codex"]) == 0                # put right: done on the next run
    assert _OLD not in _commands(setup_env.home / ".claude" / "settings.json")
    assert json.loads((setup_env.home / ".codex" / "hooks.json").read_text()) == {}


def _admin_requirements(*, matcher=None, handler_extra=""):
    """An administrator's requirements.toml with the guard's hooks as codex_requirements() writes
    them, each group and handler narrowed as given. It parses: what fails is the coverage."""
    groups = "".join(f"""
[[hooks.{event}]]
{f"matcher = {json.dumps(matcher)}" if matcher is not None else ""}

[[hooks.{event}.hooks]]
type = "command"
command = {json.dumps(system.hook_command("codex"))}
timeout = 60
{handler_extra}""" for event in ("PreToolUse", "PostToolUse"))
    text = f'# Administrator managed\n\n[features]\nhooks = true\n\n[hooks]\nmanaged_dir = "/opt/x"\n{groups}'
    tomllib.loads(text)
    return text


@pytest.mark.parametrize("narrowed", [{"matcher": "^Read$"}, {"matcher": "Bash"}, {"matcher": "mcp__.*"},
                                      {"handler_extra": "async = true\n"},
                                      {"handler_extra": "additionalContextLimit = 10\n"}])
def test_setup_keeps_codexs_own_hooks_where_the_system_hooks_cover_less(setup_env, capsys, narrowed):
    """#89 (comment on cd6d757): an administrator's requirements.toml with the guard's command, but
    in a group for Read alone, passed: setup took Codex's own hooks, which covered every tool, out,
    and Bash, apply_patch and MCP went unguarded. What counts is what the hooks cover."""
    _user_hooks(setup_env.home)
    system.CODEX_REQUIREMENTS.parent.mkdir(parents=True)
    system.CODEX_REQUIREMENTS.write_text(_admin_requirements(**narrowed))
    assert "has no hook of the guard for every tool on PreToolUse, PostToolUse" in system.holds_hooks("codex", None)
    assert system.setup("owner", ["codex"]) == 1
    assert "NOT DONE for codex" in capsys.readouterr().out
    assert f"{_OLD} --agent codex" in _commands(setup_env.home / ".codex" / "hooks.json")
    assert "Administrator managed" in system.CODEX_REQUIREMENTS.read_text()


@pytest.mark.parametrize("unrestricted", [None, "", "*"])
def test_an_administrators_requirements_that_cover_every_tool_will_do(setup_env, unrestricted):
    _user_hooks(setup_env.home)
    system.CODEX_REQUIREMENTS.parent.mkdir(parents=True)
    system.CODEX_REQUIREMENTS.write_text(_admin_requirements(matcher=unrestricted))
    assert system.holds_hooks("codex", None) == ""
    assert system.setup("owner", ["codex"]) == 0
    assert json.loads((setup_env.home / ".codex" / "hooks.json").read_text()) == {}


def test_a_codex_hook_given_less_time_than_the_guard_does_not_count(setup_env):
    system.CODEX_REQUIREMENTS.parent.mkdir(parents=True)
    system.CODEX_REQUIREMENTS.write_text(_admin_requirements(matcher="*").replace("timeout = 60", "timeout = 5"))
    assert "for every tool" in system.holds_hooks("codex", None)
    system.CODEX_REQUIREMENTS.write_text(_admin_requirements(matcher="*").replace("timeout = 60\n", ""))
    assert system.holds_hooks("codex", None) == ""                         # Codex's own default: 600 seconds


@pytest.mark.parametrize("where, layer, block", [
    ("file", {"disableAllHooks": True}, False),
    ("drop-in", {"disableAllHooks": True}, False),
    ("drop-in", {"env": {"CLAUDE_CODE_SHELL_PREFIX": "/usr/local/bin/other-prefix"}}, True),
])
def test_claude_codes_managed_hooks_switched_off_beside_them_do_not_count(setup_env, capsys, where, layer, block):
    """The same for Claude Code: its managed hooks are switched off by disableAllHooks at the
    managed level, in the file or in a drop-in beside it; and in block mode a shell prefix of
    another's leaves the output of a failing command unscanned."""
    _user_hooks(setup_env.home)
    system.CLAUDE_MANAGED.parent.mkdir(parents=True)
    if where == "file":
        system.CLAUDE_MANAGED.write_text(json.dumps(layer))
    else:
        (system.CLAUDE_MANAGED.parent / "managed-settings.d").mkdir()
        (system.CLAUDE_MANAGED.parent / "managed-settings.d" / "50-admin.json").write_text(json.dumps(layer))
    if block:
        system.CONFIG_DIR.mkdir(parents=True)
        (system.CONFIG_DIR / "config.json").write_text('{"mode": "block"}')
    assert system.setup("owner", ["claude"]) == 1
    out = capsys.readouterr().out
    assert "NOT DONE for claude" in out and ("disableAllHooks" in out or "CLAUDE_CODE_SHELL_PREFIX" in out)
    assert _OLD in _commands(setup_env.home / ".claude" / "settings.json")


def test_setup_gives_grok_hooks_of_its_own_before_it_takes_claude_codes_out(setup_env):
    """Grok runs the hooks in ~/.claude/settings.json too: taking the guard's out of there would
    take the guard from Grok, which has no system settings of its own."""
    _user_hooks(setup_env.home)
    (setup_env.home / ".grok").mkdir()
    assert system.setup("owner", ["claude"]) == 0
    grok = (setup_env.home / ".grok" / "hooks" / "jevguard.json").read_text()
    assert f"{system.CODE_ROOT}/bin/jevguard-hook --agent grok" in grok
    assert _OLD not in _commands(setup_env.home / ".claude" / "settings.json")
