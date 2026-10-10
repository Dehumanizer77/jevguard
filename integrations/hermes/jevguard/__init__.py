"""jevguard as a Hermes Agent plugin. Copy this directory to ~/.hermes/plugins/jevguard/ (or run
`jevguard install --agent hermes`, which also writes where the guard lives into `root`), then
`hermes plugins enable jevguard` and restart Hermes.

The plugin is a doorway: everything the guard does is in the guard's own code, shared with the
other agents. It needs no settings of its own; the guard's are in ~/.config/jevguard.
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))


def _root() -> str:
    try:
        with open(os.path.join(_HERE, "root")) as f:
            return f.read().strip()
    except OSError:
        return os.environ.get("JEVGUARD_ROOT", "")


def on_tool_execution(*, tool_name: str = "", args=None, next_call=None, **kw):
    root = _root()
    if root and root not in sys.path:
        sys.path.insert(0, root)
    try:
        from jevguard.agents import hermes
    except Exception:  # the guard is not where the plugin was told: do not take the agent down
        return next_call(args)
    return hermes.around(tool_name, args, next_call, kw)


def register(ctx) -> None:
    ctx.register_middleware("tool_execution", on_tool_execution)
