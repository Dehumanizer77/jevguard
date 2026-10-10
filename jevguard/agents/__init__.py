"""One adapter per agent. An adapter is everything the guard knows about that agent: how its hook
is called, what its tools are named, what shape their results have, how it is told to replace a
result or to hold a call for approval, and where its hooks are configured.

What an agent lets a hook do decides how much of the guard works there:

    agent     replace a result             ask before a call        shell output
    claude    every tool                   yes                      replaced
    grok      every tool                   yes                      replaced
    copilot   every tool                   yes                      replaced
    hermes    every tool (in process)      no: refuse with a note   replaced
    codex     every tool, by way of the    no: refuse with a note   replaced
              hook's feedback
    cursor    MCP tools; file reads are    shell and MCP; refuse    run through `jevguard-run`
              refused before they happen   for its other tools

Where an agent cannot replace what a shell command printed (Cursor), the adapter rewrites the
command so that it runs through `jevguard-run`, which scans the output before the agent gets it.

Three things an adapter must not get wrong, each of which the first version did (PR #31 review):

- Every event that comes before a tool runs has to reach the gate (phase "before"), with every
  file the call changes: also when the files are named inside a patch, and also for a tool the
  adapter has no name for. Where the agent cannot ask at that event, the answer is a refusal.
- A result is read whole. A field is left out of the scan, or kept in a replacement, only when
  its value shows it is not content (a tag, a media type, something the call itself said),
  never because of what the field is called.
- A replacement holds the notice and nothing else of the original.

And one for the engine and everything around it: once there is a verdict, or a reason to ask,
nothing that is only written down afterwards (the usage counter, the session's marks, the
quarantine, the log, a wrapper's mark) may change it. Every such write goes through
engine._record. on_error is the policy for a scan that failed, not for a record that did.
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
    from . import codex, copilot, cursor, grok
    for module in (grok, copilot, codex, cursor):
        found[module.AGENT.name] = module.AGENT
    return found  # Hermes is not here: its plugin calls agents/hermes.py in Hermes' own process


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
