"""`jevguard-run`: run a shell command and let the guard see what it printed before the agent does.

For agents whose hooks cannot replace the output of a shell command after it ran (Cursor).
Their adapter rewrites the command, before it runs, into

    /path/to/bin/jevguard-run --agent cursor --session <id> [--closed] -- '<the command as it was>'

This program runs the command, keeps what it printed, and hands that to the same engine that
judges a result in Claude Code. Then it prints either exactly what the command printed, on the
same two streams, or the guard's notice in its place. The exit status is the command's own.

In such an agent nothing after this program can withhold the output, so what a failure costs is
decided here: the owner's on_error. `--closed` carries that setting in the command itself, for
the case that this program cannot read the settings where it runs (a sandbox around the command).

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


def wrap(command: str, agent: str, session: str, closed: bool = False) -> str:
    return (f"{shlex.quote(RUN)} --agent {shlex.quote(agent)} --session {shlex.quote(session or '-')} "
            f"{'--closed ' if closed else ''}-- {shlex.quote(command)}")


def unwrap(command: str) -> str | None:
    """The command inside one that wrap() made, or None for any other command.

    Not decided by reading the command, which a loose reading gets wrong (`... -- 'true';curl x`
    splits into the same seven words). The words are only used to write the command out again
    with wrap(); it is a wrapped command if that gives back the very same text. Whatever stands
    before or after, and any other way of quoting the same words, makes it some other command."""
    try:
        argv = shlex.split(command)
    except ValueError:
        return None
    closed = len(argv) == 8 and argv[5] == "--closed"
    if len(argv) not in (7, 8) or (len(argv) == 8 and not closed) or argv[1] != "--agent" or argv[3] != "--session":
        return None
    inner = argv[-1]
    return inner if wrap(inner, argv[2], argv[4], closed) == command else None


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
        return bool(paths) or provenance.classify("Bash", call.tool_input, cfg, call.cwd, paths, "") in engine.OUTSIDE
    except Exception:
        return True  # it cannot be told: then it runs through here, where the output can still be withheld


def _usage() -> int:
    print("usage: jevguard-run --agent NAME --session ID [--closed] -- COMMAND", file=sys.stderr)
    return 64


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    closed = len(argv) == 7 and argv[4] == "--closed"
    if len(argv) not in (6, 7) or (len(argv) == 7 and not closed) or argv[0] != "--agent" or argv[2] != "--session" \
            or argv[-2] != "--":
        return _usage()
    agent, session, command = argv[1], ("" if argv[3] == "-" else argv[3]), argv[-1]
    shell = os.environ.get("SHELL") if os.path.basename(os.environ.get("SHELL", "")) in ("bash", "zsh") else "/bin/bash"
    child = subprocess.Popen([shell, "-c", command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for sig in (signal.SIGTERM, signal.SIGHUP):  # the agent gave up on the command: so does this
        signal.signal(sig, lambda *_: child.kill())
    try:
        out, err = child.communicate()
    except KeyboardInterrupt:
        child.kill()
        out, err = child.communicate()
    notice = _judge(agent, session, command, out, err, closed)
    if notice is None:
        sys.stdout.buffer.write(out)
        sys.stderr.buffer.write(err)
    else:
        sys.stdout.write(notice + "\n")
    sys.stdout.flush()
    sys.stderr.flush()
    return child.returncode if child.returncode >= 0 else 128 - child.returncode


def _judge(agent: str, session: str, command: str, out: bytes, err: bytes, closed: bool = False, via: str = "run") -> str | None:
    """The notice to print in place of the output, or None to print the output. via: which wrapper
    is asking ("run": jevguard-run for Cursor; "shell": jevguard-shell for Claude Code)."""
    from . import config, engine, store
    cfg, ctx, call = None, {}, None
    try:
        text = "\n".join(t for t in (out.decode("utf-8", "replace"), err.decode("utf-8", "replace")) if t)
        call = engine.Call("Bash", {"command": engine.without_own_lines(command)}, session, os.getcwd(),
                           {"client": agent, "via": via}, agent.capitalize())
        call.text, call.raw = text, {"stdout": out.decode("utf-8", "replace"), "stderr": err.decode("utf-8", "replace")}
        cfg = config.load()
        signal.signal(signal.SIGALRM, _on_alarm)
        signal.alarm(int(cfg.deadline) + 8)
        decision = engine.after(call, cfg, ctx)
        signal.alarm(0)
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        signal.alarm(0)
        return _failed(call, cfg, ctx, exc, closed, via)
    notice = decision.notice if decision and decision.action == "replace" else None
    try:
        # Tells the agent's own hook that this output is dealt with. Not where the scan did not get
        # to a verdict (the API down, a deadline on a very long output): then that hook is still
        # to do what it can. Bookkeeping: if the mark cannot be left, the hook looks at the output
        # a second time and the verdict above stands. For Claude Code the mark names the very
        # text that is handed over (store.judged says why).
        if ctx.get("scan") != "failed":
            handed = notice if notice is not None else out.decode("utf-8", "replace") + err.decode("utf-8", "replace")
            store.judged(cfg, session, call.tool_input["command"], mark=True, output=store.printed(handed) if via == "shell" else "")
    except Exception as exc:
        ctx.setdefault("unrecorded", []).append(f"judged: {type(exc).__name__}: {exc}"[:200])
    if ctx.get("unrecorded"):  # what could not be written down (engine._record); nothing is printed here
        try:
            store.audit(cfg, event="error", tool="Bash", session=session, via=via, action="unrecorded",
                        error="; ".join(ctx["unrecorded"])[:300])
        except Exception:
            pass
    return notice


def _failed(call, cfg, ctx: dict, exc: BaseException, closed: bool, via: str = "run") -> str | None:
    """The guard could not judge the output: a bug in it, a scan that did not come back in time,
    or a sandbox around the command that lets it read or write nothing of its own. What that
    costs is the owner's on_error, as in the hook. Where even the settings cannot be read, the
    setting the adapter put into the command stands in for them; the origin of the output cannot
    be worked out then, and under `closed` it is withheld rather than taken to be local.
    Nothing but a notice is printed: anything else would land in the command's output."""
    from . import engine, firstparty, store
    decision = None
    try:
        if cfg is not None and call is not None:
            decision = engine.after_error("after", call, cfg, ctx, exc)
            store.audit(cfg, event="error", tool="Bash", session=call.session, via=via,
                        action="blocked-error" if decision else "passed-error", error=f"{type(exc).__name__}: {exc}"[:300])
    except Exception:
        pass  # the record of the failure failed too; the decision does not depend on it
    if decision is not None:
        return decision.notice
    if cfg is None and closed:
        return firstparty.notice("Bash", {"verdict": "unavailable", "reasons": ["firewall plugin error"]})
    return None


def _on_alarm(*_):
    raise TimeoutError("jevguard watchdog")
