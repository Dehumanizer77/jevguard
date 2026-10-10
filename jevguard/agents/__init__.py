"""One adapter per agent. An adapter is everything the guard knows about that agent: how its hook
is called, what its tools are named, what shape their results have, how it is told to replace a
result or to hold a call for approval, and where its hooks are configured.

What an agent lets a hook do decides how much of the guard works there:

    agent     replace a result             ask before a call        shell output
    claude    every tool                   yes                      replaced
    grok      every tool                   yes                      replaced
    copilot   every tool                   yes                      replaced
    hermes    every tool (in process)      no: refuse with a note   replaced
    cursor    MCP tools; file reads are    shell and MCP            run through `jevguard run`
              refused before they happen
    codex     MCP tools                    yes                      run through `jevguard run`

Where an agent cannot replace what a shell command printed, the adapter rewrites the command
so that it runs through `jevguard run`, which scans the output before the agent gets it.
"""

from __future__ import annotations

from ..engine import Call, Decision


class Agent:
    name = ""    # as given to --agent and to `jevguard install --agent`
    title = ""   # as written in a question: "Claude says: ..."

    def detect(self, d: dict, env) -> bool:
        """This hook input is this agent's. Used when the hook is started without --agent, which
        is how another agent starts it when it reads Claude Code's settings."""
        return False

    def read(self, d: dict) -> tuple[str, Call] | None:
        """("before" | "after", the call in the engine's vocabulary), or None for an event the
        guard has nothing to do with."""
        raise NotImplementedError

    def answer(self, d: dict, phase: str, call: Call, decision: Decision) -> dict | None:
        """What the hook prints for this decision, in the agent's own format."""
        raise NotImplementedError

    def untouched(self, d: dict, phase: str, call: Call) -> dict | None:
        """What the hook prints when the engine has nothing to say. Nothing, as a rule; an agent
        whose shell output cannot be replaced afterwards has the command rewritten here."""
        return None


def all_agents() -> dict:
    from . import claude
    found = {a.name: a for a in (claude.ClaudeCode(),)}
    for module in ("grok", "copilot", "codex", "cursor"):
        try:
            mod = __import__(f"{__name__}.{module}", fromlist=["AGENT"])
        except ImportError:
            continue
        found[mod.AGENT.name] = mod.AGENT
    return found


def pick(d: dict, argv: list[str], env) -> Agent:
    """--agent NAME when given; else whichever adapter recognises the input; else Claude Code."""
    agents = all_agents()
    if "--agent" in argv[:-1]:
        name = argv[argv.index("--agent") + 1]
        if name not in agents:
            raise ValueError(f"no adapter for agent {name!r}")
        return agents[name]
    for name, agent in agents.items():
        if name != "claude" and agent.detect(d, env):
            return agent
    return agents["claude"]
