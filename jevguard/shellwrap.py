"""`jevguard-shell`: in Claude Code, how the guard gets to see what a shell command printed before
Claude Code does.

Claude Code runs every shell command through the program named in CLAUDE_CODE_SHELL_PREFIX (the
guard's `install` sets it, in block mode): `jevguard-shell '<line>'`, where for a tool's command
the line is (seen in 2.1.295, the same for Bash and for Monitor)

    source <snapshot> ... && eval '<the command>' < /dev/null && pwd -P >| /tmp/claude-XXXX-cwd

and for a hook it is the hook's own command. What the prefix prints is what Claude Code gets.

Why this and not the hook after the call alone. That hook is not started for a command that
exits with an error status: Claude Code starts PostToolUseFailure instead, where nothing can be
replaced, and the output went to the model unscanned. It is also given only the first 30,000
characters of a long output, and nothing of a command killed for running too long. Here the
output is held, judged whole, and printed or replaced, whatever the exit status, and the command
the owner sees and approves stays as the agent wrote it.

Everything Claude Code runs goes through this, so it is built to get out of the way:

- `bin/jevguard-shell` is a few lines of sh. Only a line with an `eval` in it comes here; a hook
  is run as it is.
- capture() decides, before anything runs, whether this command's output would be looked at.
  If not (a local command, log mode, a Monitor, anything unexpected, any error), the caller runs
  the line itself and its output streams as always.
- run() never raises once the command has been started: whatever goes wrong after that is
  handled as run.py handles it for Cursor (the verdict stands; a failure costs what on_error says).

Inside Claude Code's own sandbox this program is inside it too, with no network and no file of
its own: then it cannot scan, says nothing, and the hooks do what they did before.
"""

from __future__ import annotations

import os
import shlex
import signal
import subprocess
import sys


def command_of(line: str) -> str | None:
    """The command a tool asked for, out of the line Claude Code builds around it. None for a
    line of any other shape: a hook's command, or a later version's line this does not know."""
    try:
        argv = shlex.split(line)
    except ValueError:
        return None
    if not argv or argv[0] != "source" or argv.count("eval") != 1:
        return None
    at = argv.index("eval")
    return argv[at + 1] if at + 1 < len(argv) else None


def capture(line: str) -> tuple | None:
    """(session, command, closed) when what this line prints is to be held and judged, else None.
    Nothing has been run when this returns or raises."""
    command = command_of(line)
    if command is None:
        return None
    from . import config, engine, provenance, store
    cfg = config.load()
    if cfg.mode != "block":
        return None  # nothing is withheld in log mode; the hooks do the logging
    session = os.environ.get("CLAUDE_CODE_SESSION_ID", "")
    asked = engine.without_own_lines(command)
    if store.streamed(cfg, session, asked):
        return None  # a Monitor: asked about before it started if it reads from outside (engine.before)
    if not cfg.scan_local:
        try:
            state = store.session(cfg, session)
            paths = [*state.get("paths", []), *engine._task_outputs({"command": asked}, os.getcwd(), list(state.get("tasks", [])))]
            if provenance.classify("Bash", {"command": asked}, cfg, os.getcwd(), engine._existing(cfg, paths), "") not in engine.OUTSIDE:
                return None  # local: runs as it is, its output streams as always
        except (ValueError, OSError):
            pass  # which files this session downloaded is not known: held, it may print one of them
    return session, command, cfg.on_error == "closed"


def run(shell: str, line: str, plan: tuple) -> int:
    """Run the line, keep what it prints, and print that or the guard's notice. Never raises."""
    session, command, closed = plan
    try:
        child = subprocess.Popen([shell, "-c", line], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception:
        os.execv(shell, [shell, "-c", line])  # it did not start here: let it start, or fail, as it would have
    for sig in (signal.SIGTERM, signal.SIGHUP):  # Claude Code gave up on the command: so does this, printing nothing
        signal.signal(sig, lambda *_: (child.kill(), os._exit(143)))
    try:
        out, err = child.communicate()
    except KeyboardInterrupt:
        child.kill()
        out, err = child.communicate()
    notice = None
    try:
        from .run import _judge
        notice = _judge("claude", session, command, out, err, closed, via="shell")
    except BaseException:  # _judge keeps its failures to itself; this is for one that could not even be loaded
        notice = None
    try:
        if notice is None:
            sys.stdout.buffer.write(out)
            sys.stderr.buffer.write(err)
        else:
            sys.stdout.write(notice + "\n")
        sys.stdout.flush()
        sys.stderr.flush()
    except Exception:
        pass
    return child.returncode if child.returncode >= 0 else 128 - child.returncode
