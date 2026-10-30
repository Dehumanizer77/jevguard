"""A system installation: the guard put by root where the agent's user cannot change it.

The code lies in a directory only root can write (`/opt/jevguard`), its settings in
`/etc/jevguard`, and the agents' hooks in their system settings
(`/etc/claude-code/managed-settings.json`, `/etc/codex/requirements.toml`), which nothing in the
user's own settings can switch off. The API key, the seal key, the scan log, the quarantine, the
release list and the sessions' state belong to the system user `jevguard`. A service running as
that user (service.py) holds them. The hook still runs as the user the agent runs as, so that it
reads the files the agent reads, and asks the service over a socket for whatever needs the key or
the guard's state. The owner's commands that change the guard need root (`sudo jevguard mode
block`).

What it does not stop:
- A process of the agent's user that is root in all but name: in the `docker` or `disk` group,
  or with sudo that asks for no password. It can still change all of this.
- One that may ptrace the agent's processes (`kernel.yama.ptrace_scope` 0): it can change what a
  hook answers.
- The socket answers the agent's other processes as it answers the hook. They can have a text
  scored or sealed, or things recorded in a session's state. The service keeps its files from
  being read or changed, not from being asked.
"""

from __future__ import annotations

import grp
import json
import os
import pwd
import re
import shutil
import subprocess
import time
from pathlib import Path

CODE_ROOT = Path(__file__).resolve().parent.parent
SYSTEM_FILE = Path("/etc/jevguard/system.json")  # names the code of the installation, and its owners
CONFIG_DIR = Path("/etc/jevguard")
STATE_DIR = Path("/var/lib/jevguard")
RELEASED_DIR = Path("/var/lib/jevguard-released")
SOCKET = "/run/jevguard/hook.sock"
USER = "jevguard"
UNITS = Path("/etc/systemd/system")
CLAUDE_MANAGED = Path("/etc/claude-code/managed-settings.json")
CODEX_REQUIREMENTS = Path("/etc/codex/requirements.toml")
COMMAND_LINK = Path("/usr/local/bin/jevguard")
_OURS = "# Written by jevguard setup-system, which rewrites this file. Add nothing here: it would be lost.\n"


def settings() -> dict | None:
    """The system installation this code is part of, or None. It is one only where SYSTEM_FILE
    names this very code, and that file is root's and writable by root alone: a file anyone else
    could have written says nothing."""
    try:
        st = SYSTEM_FILE.stat()
        found = json.loads(SYSTEM_FILE.read_text())
    except (OSError, ValueError):
        return None
    if st.st_uid != 0 or st.st_mode & 0o022 or not isinstance(found, dict):
        return None
    if os.path.realpath(str(found.get("code", ""))) != str(CODE_ROOT):
        return None
    return found


def service_ids() -> tuple[int, int]:
    """(uid, gid) of the user the service runs as."""
    pw = pwd.getpwnam(USER)
    return pw.pw_uid, pw.pw_gid


def become_service_user() -> None:
    """Root only: go on as the user jevguard, whose the guard's state is, so that what the
    owner's command writes there stays the service's to read and change."""
    uid, gid = service_ids()
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    os.umask(0o077)


# ---- what root writes: units, the agents' system settings ----------------------------------------

def units() -> dict[str, str]:
    """The service and its socket. The socket takes any local user; the service answers only the
    owners named in SYSTEM_FILE (and root), by the credentials the kernel gives for the socket."""
    socket_unit = f"""[Unit]
Description=jevguard prompt-injection guard: socket of its service

[Socket]
ListenStream={SOCKET}
SocketUser={USER}
SocketGroup={USER}
SocketMode=0666
DirectoryMode=0755

[Install]
WantedBy=sockets.target
"""
    service_unit = f"""[Unit]
Description=jevguard prompt-injection guard: holds its API key and its state
Requires=jevguard.socket
After=network-online.target

[Service]
User={USER}
Group={USER}
ExecStart=/usr/bin/python3 -IS {CODE_ROOT}/bin/jevguard-service
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths={STATE_DIR} {RELEASED_DIR}
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=yes
RestrictRealtime=yes

[Install]
WantedBy=multi-user.target
"""
    return {"jevguard.socket": socket_unit, "jevguard.service": service_unit}


def hook_command(agent: str) -> str:
    return f"{CODE_ROOT}/bin/jevguard-hook --agent {agent}"


def _ours(command) -> bool:
    """A hook command or a shell prefix of a jevguard installation, wherever its code lies."""
    return isinstance(command, str) and bool(re.search(r"/bin/jevguard-(?:hook|shell)(?:\s|$)", command))


def claude_settings(cfg, current: dict, remove: bool = False) -> dict:
    """Claude Code's managed settings with the guard's hooks in them, and in block mode its shell
    prefix: the same hooks `jevguard install` puts in a user's settings (cli.install), given the
    agent by name. remove: with none of them. Whatever else the file holds stays as it is."""
    from . import cli
    from .agents import setup as agent_setup
    settings = json.loads(json.dumps(current))
    env = settings.get("env") if isinstance(settings.get("env"), dict) else {}
    if _ours(env.get(cli.PREFIX_KEY)):
        del env[cli.PREFIX_KEY]
    if not remove and cfg.mode == "block" and not env.get(cli.PREFIX_KEY):
        env[cli.PREFIX_KEY] = str(CODE_ROOT / "bin" / "jevguard-shell")
    if env:
        settings["env"] = env
    else:
        settings.pop("env", None)
    hooks = settings.get("hooks") if isinstance(settings.get("hooks"), dict) else {}
    entry = {"type": "command", "command": hook_command("claude"), "timeout": 40}
    for event, (matchers, sync, wanted) in cli.hook_plan(cfg).items():
        groups = [g for g in (agent_setup.without(g, lambda h: _ours(h.get("command"))) for g in hooks.get(event, []))
                  if g is not None]
        if wanted and not remove:
            groups += [{"matcher": m, "hooks": [dict(entry) if sync else dict(entry, **{"async": True})]} for m in matchers]
        if groups:
            hooks[event] = groups
        else:
            hooks.pop(event, None)
    if hooks:
        settings["hooks"] = hooks
    else:
        settings.pop("hooks", None)
    return settings


def codex_requirements() -> str:
    """Codex's system requirements: the guard's hooks for every tool, hooks pinned on so that
    `[features] hooks = false` in the user's config.toml does not turn them off. Codex runs hooks
    from here without asking the owner to review them."""
    command = hook_command("codex")
    groups = "".join(f"""
[[hooks.{event}]]

[[hooks.{event}.hooks]]
type = "command"
command = {json.dumps(command)}
timeout = 60
""" for event in ("PreToolUse", "PostToolUse"))
    return f"""{_OURS}
[features]
hooks = true

[hooks]
managed_dir = {json.dumps(str(CODE_ROOT / "bin"))}
{groups}"""


# ---- root's part: set up, update, take away ------------------------------------------------------

def _write(path: Path, text: str | bytes, mode: int, uid: int = 0, gid: int = 0) -> None:
    """Write a file in one step, owned and readable as given. A link at the name is replaced,
    never followed."""
    data = text.encode() if isinstance(text, str) else text
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chown(tmp, uid, gid)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _directory(path: Path, mode: int, uid: int = 0, gid: int = 0) -> None:
    if path.is_symlink():
        raise OSError(f"{path} is a symbolic link; refusing to use it")
    path.mkdir(parents=True, exist_ok=True)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def check_code(root: Path = CODE_ROOT, owner: int = 0) -> list[str]:
    """Why the code could be changed by someone other than root. Every directory from / down to
    it, and every directory and file in it, has to be root's and writable by root alone: a
    directory others may write lets them replace what is in it, whoever owns that (#88). The
    whole tree, not only what is run or imported: root runs `git pull` in it, and git runs what
    lies in .git/hooks. And no link, which could lead anywhere. Empty when it is out of reach."""
    found = []

    def check(p: Path) -> None:
        st = p.lstat()
        if p.is_symlink():
            found.append(f"{p} is a symbolic link")
        elif st.st_uid != owner or st.st_mode & 0o022:
            found.append(f"{p} is not root's alone (owner {st.st_uid}, mode {oct(st.st_mode & 0o777)})")

    for p in [*reversed(root.parents), root]:
        check(p)
    for dirpath, dirnames, filenames in os.walk(root):
        for name in [*dirnames, *filenames]:
            check(Path(dirpath) / name)
    return found


def _as_owner(pw, fn, *args):
    """fn(*args) in a child process that runs as the owner, never as root: what is read from or
    written to the owner's home is then only what the owner may read and write, whatever links the
    agent may have put there. The answer comes back as JSON, which root reads as data only."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:  # the child
        code = 0
        try:
            os.close(r)
            os.setgroups(os.getgrouplist(pw.pw_name, pw.pw_gid))
            os.setgid(pw.pw_gid)
            os.setuid(pw.pw_uid)
            os.environ["HOME"] = pw.pw_dir
            out = {"result": fn(*args)}
        except BaseException as exc:  # noqa: BLE001 - reported to the parent
            out, code = {"error": f"{type(exc).__name__}: {exc}"}, 1
        with os.fdopen(w, "w") as f:
            json.dump(out, f)
        os._exit(code)
    os.close(w)
    with os.fdopen(r) as f:
        data = f.read()
    os.waitpid(pid, 0)
    out = json.loads(data or '{"error": "no answer"}')
    if "error" in out:
        raise RuntimeError(out["error"])
    return out["result"]


_STATE_FILES = ("released.txt", "released-files.json", "scans.jsonl", "scans.jsonl.1", "seal.key", "usage.json")
_QUARANTINE_NAME = re.compile(r"fw-\d{8}-[0-9a-f]{6}\.json")
_RELEASED_NAME = re.compile(r"fw-\d{8}-[0-9a-f]{6}(?:\.txt|-\d+\.[a-z]+)")


def _read_user_installation() -> dict:
    """Run as the owner (_as_owner): the settings, key and state of the owner's own installation,
    as base64, for setup to bring over. Only plain files, read without following a link."""
    import base64
    home = Path.home()
    cfg_dir, state_dir = home / ".config" / "jevguard", home / ".local" / "state" / "jevguard"
    released_dir = home / ".local" / "state" / "jevguard-released"

    def read(p: Path) -> str | None:
        try:
            fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            return None
        with os.fdopen(fd, "rb") as f:
            import stat
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                return None
            return base64.b64encode(f.read()).decode()

    def listing(d: Path, pattern: re.Pattern) -> dict:
        try:
            names = sorted(p.name for p in d.iterdir() if pattern.fullmatch(p.name))
        except OSError:
            return {}
        return {n: data for n in names if (data := read(d / n)) is not None}

    return {"config": read(cfg_dir / "config.json"), "key": read(cfg_dir / "typesafe.key"),
            "state": {n: data for n in _STATE_FILES if (data := read(state_dir / n)) is not None},
            "quarantine": listing(state_dir / "quarantine", _QUARANTINE_NAME),
            "released": listing(released_dir, _RELEASED_NAME),
            "paths": [str(cfg_dir / "typesafe.key"), str(state_dir), str(released_dir)]}


def _remove_user_hooks(agents: list[str]) -> list[str]:
    """Run as the owner (_as_owner): the guard's hooks taken out of the owner's own settings for
    these agents, whose system settings run the guard now (and only for those, #89), so that they
    do not run a second time beside the system's. Other hooks stay. What was changed, for the
    report.

    Grok runs the hooks in ~/.claude/settings.json as well. Where it is there and has no hooks of
    the guard of its own, it gets them (~/.grok/hooks/jevguard.json, this code) before Claude
    Code's are taken out: else it would lose the guard it had."""
    from .agents import setup as agent_setup
    done = []
    files = {"claude": Path.home() / ".claude" / "settings.json", "codex": Path.home() / ".codex" / "hooks.json"}
    if "claude" in agents and (Path.home() / ".grok").is_dir() and not agent_setup.installed("grok"):
        done.append(f"Grok runs Claude Code's hooks as well: {agent_setup.install('grok')}")
    for path in (files[a] for a in agents if a in files):
        try:
            settings = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        if not isinstance(settings, dict):
            continue
        before = json.dumps(settings, sort_keys=True)
        hooks = settings.get("hooks") if isinstance(settings.get("hooks"), dict) else {}
        for event in list(hooks):
            groups = [g for g in (agent_setup.without(g, lambda h: _ours(h.get("command"))) for g in hooks[event] or [])
                      if g is not None]
            if groups:
                hooks[event] = groups
            else:
                del hooks[event]
        if not hooks:
            settings.pop("hooks", None)
        env = settings.get("env")
        if isinstance(env, dict) and _ours(env.get("CLAUDE_CODE_SHELL_PREFIX")):
            del env["CLAUDE_CODE_SHELL_PREFIX"]
            if not env:
                del settings["env"]
        if json.dumps(settings, sort_keys=True) == before:
            continue
        backup = path.with_name(f"{path.name}.jevguard-{time.strftime('%Y%m%d-%H%M%S')}.bak")
        shutil.copy2(path, backup)
        tmp = path.with_name(path.name + ".jevguard-tmp")
        tmp.write_text(json.dumps(settings, indent=2, ensure_ascii=False) + "\n")
        tmp.replace(path)
        done.append(f"took the guard's own hooks out of {path} (backup: {backup.name})")
    return done


def _bring_over(found: dict, uid: int, gid: int, report) -> None:
    """Settings, key and state of the owner's own installation, put where the system's are, where
    the system has none yet. Nothing that is already there is replaced."""
    import base64
    from . import config
    if found.get("config") and not (CONFIG_DIR / "config.json").exists():
        try:
            settings = json.loads(base64.b64decode(found["config"]))
            if not isinstance(settings, dict):
                raise ValueError("not an object")
        except ValueError as exc:
            report(f"the settings of the owner's installation could not be read ({exc}); starting from the defaults")
            settings = {}
        settings = {k: v for k, v in settings.items() if k in config.DEFAULTS and k != "key_file"}
        _write(CONFIG_DIR / "config.json", json.dumps(settings, indent=2) + "\n", 0o644)
        report(f"settings brought over to {CONFIG_DIR / 'config.json'}")
    key = base64.b64decode(found["key"]).decode("utf-8", "replace").strip() if found.get("key") else ""
    if key and not (CONFIG_DIR / "typesafe.key").exists():
        if not re.fullmatch(r"[\x21-\x7e]{8,512}", key):
            raise ValueError("the key in the owner's installation does not look like an API key; not brought over")
        _write(CONFIG_DIR / "typesafe.key", key + "\n", 0o640, 0, gid)
        report(f"API key brought over to {CONFIG_DIR / 'typesafe.key'}")
    for name, data in found.get("state", {}).items():
        if name in _STATE_FILES and not (STATE_DIR / name).exists():
            _write(STATE_DIR / name, base64.b64decode(data), 0o600, uid, gid)
    _directory(STATE_DIR / "quarantine", 0o700, uid, gid)
    for name, data in found.get("quarantine", {}).items():
        if _QUARANTINE_NAME.fullmatch(name) and not (STATE_DIR / "quarantine" / name).exists():
            _write(STATE_DIR / "quarantine" / name, base64.b64decode(data), 0o600, uid, gid)
    for name, data in found.get("released", {}).items():
        if _RELEASED_NAME.fullmatch(name) and not (RELEASED_DIR / name).exists():
            _write(RELEASED_DIR / name, base64.b64decode(data), 0o644, uid, gid)
    if found.get("state") or found.get("quarantine"):
        report(f"state brought over to {STATE_DIR}: {len(found.get('quarantine', {}))} quarantined results, "
               f"{', '.join(sorted(found.get('state', {}))) or 'no other files'}")


def holds_hooks(agent: str, cfg) -> str:
    """Why the agent's system settings, as they are on disk, do not run the guard: empty when
    they do. Read back after writing, so that setup never takes the owner's own hooks away for an
    agent whose system settings did not get them (#89)."""
    from . import cli
    try:
        if agent == "claude":
            hooks = json.loads(CLAUDE_MANAGED.read_text()).get("hooks") or {}
            missing = [event for event, (matchers, _, wanted) in cli.hook_plan(cfg).items() if wanted and not all(
                any(g.get("matcher") == m and any(h.get("command") == hook_command("claude") for h in g.get("hooks", []))
                    for g in hooks.get(event, [])) for m in matchers)]
            return f"{CLAUDE_MANAGED} has no hook of the guard for {', '.join(missing)}" if missing else ""
        import tomllib
        req = tomllib.loads(CODEX_REQUIREMENTS.read_text())
        hooks = req.get("hooks") or {}
        missing = [event for event in ("PreToolUse", "PostToolUse") if not any(
            h.get("command") == hook_command("codex") for g in hooks.get(event, []) for h in g.get("hooks", []))]
        if missing:
            return f"{CODEX_REQUIREMENTS} has no hook of the guard for {', '.join(missing)}"
        return "" if (req.get("features") or {}).get("hooks") is True else f"{CODEX_REQUIREMENTS} does not pin hooks on"
    except (OSError, ValueError, AttributeError, TypeError) as exc:
        return f"its system settings could not be read: {exc}"


def update_agents(cfg, agents: list[str], report=print) -> dict[str, str]:
    """Write the agents' system settings from the current settings (setup, and the owner's `mode`
    and `gate`). For each agent, why its system settings do not run the guard (holds_hooks):
    empty where they do."""
    if "claude" in agents:
        try:
            current = json.loads(CLAUDE_MANAGED.read_text())
        except FileNotFoundError:
            current = {}
        if not isinstance(current, dict):
            raise ValueError(f"{CLAUDE_MANAGED} does not hold a JSON object")
        wanted = claude_settings(cfg, current)
        if wanted != current:
            _directory(CLAUDE_MANAGED.parent, 0o755)
            if CLAUDE_MANAGED.exists():
                shutil.copy2(CLAUDE_MANAGED, CLAUDE_MANAGED.with_name(
                    f"{CLAUDE_MANAGED.name}.jevguard-{time.strftime('%Y%m%d-%H%M%S')}.bak"))
            _write(CLAUDE_MANAGED, json.dumps(wanted, indent=2) + "\n", 0o644)
            report(f"wrote {CLAUDE_MANAGED}")
    if "codex" in agents:
        text = codex_requirements()
        try:
            current = CODEX_REQUIREMENTS.read_text()
        except FileNotFoundError:
            current = None
        if current is not None and not current.startswith(_OURS):
            if holds_hooks("codex", cfg):
                report(f"left {CODEX_REQUIREMENTS} as it is: it was not written by jevguard. Add this to it, and "
                       f"run setup again:\n{text}")
        elif current != text:
            _directory(CODEX_REQUIREMENTS.parent, 0o755)
            _write(CODEX_REQUIREMENTS, text, 0o644)
            report(f"wrote {CODEX_REQUIREMENTS}")
    return {agent: holds_hooks(agent, cfg) for agent in agents}


def _works_for_owner(agents: list[str]) -> dict[str, str]:
    """Run as the owner (_as_owner): for each agent, why the guard does not work for it as that
    agent will run it, empty when it does. The owner can read the agent's system settings, the
    hook runs for that agent without an error, and the service answers the owner and has a key."""
    try:
        from .service import Client
        service = Client(timeout=30).call("scanner_available")
    except OSError as exc:
        service = f"the service does not answer the owner: {exc}"
    found = {}
    for agent in agents:
        path = CLAUDE_MANAGED if agent == "claude" else CODEX_REQUIREMENTS
        event = {"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": "/dev/null"},
                 "session_id": "jevguard-setup", "cwd": "/", "tool_use_id": "jevguard-setup"}
        try:
            path.read_text()
            r = subprocess.run([str(CODE_ROOT / "bin" / "jevguard-hook"), "--agent", agent], input=json.dumps(event),
                               text=True, capture_output=True, timeout=60,
                               env={"PATH": "/usr/bin:/bin", "HOME": str(Path.home())})
            hook = f"its hook failed: {(r.stderr or r.stdout).strip()[-300:]}" if r.returncode or r.stderr.strip() else ""
        except (OSError, subprocess.SubprocessError) as exc:
            hook = f"{type(exc).__name__}: {exc}"
        found[agent] = hook or service
    return found


def _systemctl(*args: str) -> None:
    subprocess.run(["systemctl", *args], check=True)


def setup(owner: str, agents: list[str], report=print) -> int:
    """Install the guard for the system, from the code this runs from, for one owner (the user
    the agents run as). Run again after an update: it changes only what is not as it should be."""
    from . import config
    if os.geteuid() != 0:
        report("setup-system has to be run as root: sudo jevguard setup-system --user NAME")
        return 1
    problems = check_code()
    if problems:
        report("the code is not out of the agent's reach, so nothing was installed:")
        for p in problems[:20]:
            report("  " + p)
        report(f"clone it as root to a directory only root can write, e.g. sudo git clone <url> /opt/jevguard")
        return 1
    pw = pwd.getpwnam(owner)
    if pw.pw_uid == 0:
        report("the owner is the user the agents run as, not root")
        return 1
    try:
        grp.getgrnam(USER)
    except KeyError:
        subprocess.run(["groupadd", "--system", USER], check=True)
    try:
        pwd.getpwnam(USER)
    except KeyError:
        subprocess.run(["useradd", "--system", "--gid", USER, "--home-dir", str(STATE_DIR), "--no-create-home",
                        "--shell", "/usr/sbin/nologin", "--comment", "jevguard prompt-injection guard", USER], check=True)
    uid, gid = service_ids()
    _directory(CONFIG_DIR, 0o755)
    _directory(STATE_DIR, 0o700, uid, gid)
    _directory(RELEASED_DIR, 0o755, uid, gid)
    found = _as_owner(pw, _read_user_installation)
    _bring_over(found, uid, gid, report)
    try:
        system = json.loads(SYSTEM_FILE.read_text()) if SYSTEM_FILE.exists() else {}
    except ValueError:
        system = {}
    users = sorted({*[u for u in system.get("users", []) if isinstance(u, int)], pw.pw_uid})
    _write(SYSTEM_FILE, json.dumps({"code": str(CODE_ROOT), "users": users, "agents": sorted(agents)}, indent=2) + "\n",
           0o644)
    if not (CONFIG_DIR / "typesafe.key").exists():
        report(f"no API key yet: put it in {CONFIG_DIR / 'typesafe.key'} (root:{USER}, mode 640), see the README")
    for name, text in units().items():
        _write(UNITS / name, text, 0o644)
    _systemctl("daemon-reload")
    _systemctl("enable", "--now", "jevguard.socket")
    _systemctl("try-restart", "jevguard.service")
    report(f"service: jevguard.socket and jevguard.service, as user {USER}")
    cfg = config.load()
    written = update_agents(cfg, agents, report)
    if COMMAND_LINK.is_symlink() or not COMMAND_LINK.exists():
        tmp = COMMAND_LINK.with_name(".jevguard.tmp")
        tmp.unlink(missing_ok=True)
        tmp.symlink_to(CODE_ROOT / "bin" / "jevguard")
        tmp.replace(COMMAND_LINK)
    subprocess.run(["/usr/bin/python3", "-I", "-m", "compileall", "-q", str(CODE_ROOT / "jevguard")], check=False)
    # The owner's own hooks come out only for an agent the system installation was seen to run
    # the guard for: its system settings hold the hooks, and as the owner they can be read, the
    # hook runs and the service answers (#89). For any other agent they stay as they are.
    works = _as_owner(pw, _works_for_owner, [a for a in agents if not written[a]])
    failed = {a: written[a] or works.get(a, "") for a in agents if written[a] or works.get(a)}
    for agent, why in failed.items():
        report(f"NOT DONE for {agent}: {why}. Its hooks in {owner}'s own settings were left as they are.")
    for line in _as_owner(pw, _remove_user_hooks, [a for a in agents if a not in failed]):
        report(line)
    key_copy, state_copy, released_copy = found.get("paths", [None, None, None])
    left = [p for p, there in ((key_copy, found.get("key")), (state_copy, found.get("state") or found.get("quarantine")),
                               (released_copy, found.get("released"))) if p and there]
    if failed:  # the hooks left in the owner's settings still use those copies
        report("The installation is not complete: run setup again once the above is put right.")
        return 1
    if left:
        report("The owner's own copies are still where they were, and the agent can read them. Once the system "
               "installation works, the owner removes them:")
        report("  rm -r " + " ".join(left))
    report("Start new sessions of the agents; a running session keeps the hooks it started with.")
    return 0


def remove(report=print) -> int:
    """Take the guard out of the agents' system settings and stop its service. The settings, key
    and state stay, for the owner to delete or to set up again."""
    if os.geteuid() != 0:
        report("remove-system has to be run as root")
        return 1
    try:
        current = json.loads(CLAUDE_MANAGED.read_text())
    except (OSError, ValueError):
        current = None
    if isinstance(current, dict):
        from . import config
        cleared = claude_settings(config.load(), current, remove=True)
        if cleared != current:
            _write(CLAUDE_MANAGED, json.dumps(cleared, indent=2) + "\n", 0o644)
            report(f"took the guard out of {CLAUDE_MANAGED}")
    try:
        if CODEX_REQUIREMENTS.read_text().startswith(_OURS):
            CODEX_REQUIREMENTS.unlink()
            report(f"removed {CODEX_REQUIREMENTS}")
    except OSError:
        pass
    subprocess.run(["systemctl", "disable", "--now", "jevguard.socket", "jevguard.service"], check=False)
    for name in units():
        (UNITS / name).unlink(missing_ok=True)
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    SYSTEM_FILE.unlink(missing_ok=True)
    if COMMAND_LINK.is_symlink() and os.readlink(COMMAND_LINK) == str(CODE_ROOT / "bin" / "jevguard"):
        COMMAND_LINK.unlink()
    report(f"stopped the service. Left in place: {CONFIG_DIR}, {STATE_DIR}, {RELEASED_DIR}, {CODE_ROOT}, and the "
           f"user {USER}")
    report("The agents now run without the guard: setup took its hooks out of the owners' own settings. Install it "
           "again, for the system or in a home (README, Install).")
    return 0
