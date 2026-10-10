"""`jevguard-run`: run a shell command and let the guard see what it printed before the agent does.

For agents whose hooks cannot replace the output of a shell command after it ran (Cursor).
Their adapter rewrites the command, before it runs, into

    /path/to/bin/jevguard-run --agent cursor --session <id> -- '<the command as it was>'

This program runs the command, keeps what it printed, and hands that to the same engine that
judges a result in Claude Code. Then it prints either exactly what the command printed, on the
same two streams, or the guard's notice in its place. The exit status is the command's own.

The output is held until the command has finished: it cannot be judged in pieces. An agent
that shows a command's output as it comes will show it at the end instead.
"""

from __future__ import annotations

import os
import shlex
import signal
import subprocess
import sys
from pathlib import Path

RUN = str(Path(__file__).resolve().parent.parent / "bin" / "jevguard-run")


def wrap(command: str, agent: str, session: str) -> str:
    return f"{shlex.quote(RUN)} --agent {shlex.quote(agent)} --session {shlex.quote(session or '-')} -- {shlex.quote(command)}"


def unwrap(command: str) -> str | None:
    """The command inside one that wrap() made, or None for any other command. Only the exact
    form counts: this program, its two options, `--`, and one argument."""
    try:
        argv = shlex.split(command)
    except ValueError:
        return None
    if len(argv) == 7 and argv[0] == RUN and argv[1] == "--agent" and argv[3] == "--session" and argv[5] == "--":
        return argv[6]
    return None


def wanted(call, cfg) -> bool:
    """The guard would look at what this shell command prints, so it has to run through here:
    the command fetches from outside or reads a file that came from there, or local output is
    scanned too, or this session has downloaded files that any command might print."""
    from . import engine, provenance, store
    if cfg.mode != "block":
        return False  # nothing is replaced in log mode; the agent's own after-hook does the logging
    if cfg.scan_local:
        return True
    try:
        paths = engine._existing(cfg, store.session(cfg, call.session).get("paths", []))
    except (ValueError, OSError):
        return True
    return bool(paths) or provenance.classify("Bash", call.tool_input, cfg, call.cwd, paths, "") in engine.OUTSIDE


def _usage() -> int:
    print("usage: jevguard-run --agent NAME --session ID -- COMMAND", file=sys.stderr)
    return 64


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 6 or argv[0] != "--agent" or argv[2] != "--session" or argv[4] != "--":
        return _usage()
    agent, session, command = argv[1], ("" if argv[3] == "-" else argv[3]), argv[5]
    shell = os.environ.get("SHELL") if os.path.basename(os.environ.get("SHELL", "")) in ("bash", "zsh") else "/bin/bash"
    child = subprocess.Popen([shell, "-c", command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for sig in (signal.SIGTERM, signal.SIGHUP):  # the agent gave up on the command: so does this
        signal.signal(sig, lambda *_: child.kill())
    try:
        out, err = child.communicate()
    except KeyboardInterrupt:
        child.kill()
        out, err = child.communicate()
    notice = _judge(agent, session, command, out, err)
    if notice is None:
        sys.stdout.buffer.write(out)
        sys.stderr.buffer.write(err)
    else:
        sys.stdout.write(notice + "\n")
    sys.stdout.flush()
    sys.stderr.flush()
    return child.returncode if child.returncode >= 0 else 128 - child.returncode


def _judge(agent: str, session: str, command: str, out: bytes, err: bytes) -> str | None:
    """The notice to print in place of the output, or None to print the output."""
    from . import config, engine, store
    cfg, ctx, call = None, {}, None
    try:
        text = "\n".join(t for t in (out.decode("utf-8", "replace"), err.decode("utf-8", "replace")) if t)
        call = engine.Call("Bash", {"command": engine.without_own_lines(command)}, session, os.getcwd(),
                           {"client": agent, "via": "run"}, agent.capitalize())
        call.text, call.raw = text, {"stdout": out.decode("utf-8", "replace"), "stderr": err.decode("utf-8", "replace")}
        cfg = config.load()
        signal.signal(signal.SIGALRM, _on_alarm)
        signal.alarm(int(cfg.deadline) + 8)
        decision = engine.after(call, cfg, ctx)
        signal.alarm(0)
        # tells the agent's own hook that this output is dealt with
        store.judged(cfg, session, call.tool_input["command"], mark=True)
    except BaseException as exc:
        # The wrapper could not do its work: a guard bug, or a sandbox around the command that
        # allows neither the network nor a file of the guard's own. The output goes through as
        # it is and nothing is marked, so the agent's hook after the call, which runs outside
        # that sandbox, judges it. Nothing is printed: it would land in the output.
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        signal.alarm(0)
        return None
    return decision.notice if decision and decision.action == "replace" else None


def _on_alarm(*_):
    raise TimeoutError("jevguard watchdog")
