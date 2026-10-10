"""Hook entry point, for every agent that runs a command as its hook. Reads the hook input on
stdin, lets the agent's adapter turn it into a call the engine understands, and prints the
engine's decision in that agent's format.

    jevguard-hook                  Claude Code, or whichever agent the input turns out to be from
    jevguard-hook --agent cursor   the agent named

In "log" mode nothing is printed after a call, so the hook can run without holding the agent up.
In "block" mode a result that scores as an injection is replaced whole by a short notice. Text
is never added to a result: a warning inside it is one more instruction-like passage to read.
"""

from __future__ import annotations

import json
import os
import signal
import sys

from . import agents, config, engine, store


def _on_alarm(*_):
    raise TimeoutError("jevguard watchdog")


def main() -> None:
    out, d, cfg, ctx, agent, phase, call = None, {}, None, {}, None, "", None
    try:
        d = json.loads(sys.stdin.read() or "{}")
        cfg = config.load()
        signal.signal(signal.SIGALRM, _on_alarm)
        signal.alarm(int(cfg.deadline) + 8)
        agent = agents.pick(d, sys.argv[1:], os.environ)
        read = agent.read(d)
        if read:
            phase, call = read
            # "after": a result to judge; "before": a call to gate; anything else: an event where the
            # agent takes no decision, and its adapter may still rewrite the call
            decision = (engine.after(call, cfg, ctx) if phase == "after" else
                        engine.before(call, cfg) if phase == "before" else None)
            out = agent.answer(d, phase, call, decision) if decision else agent.untouched(d, phase, call)
    except BaseException as exc:  # a guard bug must not take the session down
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        print(f"jevguard: {type(exc).__name__}: {exc}", file=sys.stderr)
        try:
            signal.alarm(0)
            agent = agent or agents.pick(d, sys.argv[1:], os.environ)
            if call is None:
                read = agent.read(d)
                phase, call = read if read else ("", None)
            decision = engine.after_error(phase, call, cfg, ctx, exc)
            out = agent.answer(d, phase, call, decision) if decision else None
            store.audit(cfg or config.load(), event="error", tool=call.tool if call else None,
                        session=call.session if call else None,
                        action=("asked-error" if phase == "before" else "blocked-error") if out else "passed-error",
                        error=f"{type(exc).__name__}: {exc}"[:300])
        except Exception:
            pass
    if out is not None:
        sys.stdout.write(json.dumps(out, ensure_ascii=False))
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)  # do not wait for scoring threads that are past the deadline
