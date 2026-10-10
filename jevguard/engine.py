"""What to do with a tool call, and with what it returned, whichever agent it belongs to.

The engine speaks one vocabulary for tools, the one this guard started with:

    Bash        tool_input: command, description
    Read, Grep  tool_input: file_path or path
    WebFetch    tool_input: url
    WebSearch
    Write, Edit, NotebookEdit   tool_input: file_path
    mcp__<server>__<tool>       anything that brings content in from outside

An adapter (jevguard/agents) turns its agent's tool calls into a Call in that vocabulary and a
Decision back into what its agent understands. The engine knows nothing about any agent: not
the names of its tools, not the shape of their results, not how it is told to ask or to replace.
"""

from __future__ import annotations

import os
import time

from . import config, store

UNKNOWN = "unknown"  # the origin of a result was not established before something failed
# Origins that are content from outside, however strictly each is then handled (see provenance.py).
OUTSIDE = ("external", "trusted", "own")


class Call:  # plain classes: the hook starts for every tool call, and dataclasses cost an import
    def __init__(self, tool: str, tool_input: dict, session: str = "", cwd: str = "", ids: dict | None = None,
                 who: str = "Claude"):
        self.tool = tool              # in the vocabulary above
        self.tool_input = tool_input
        self.session, self.cwd = session, cwd
        self.ids = ids or {}          # tool_use_id, agent, client: kept in the log
        self.who = who                # what the agent is called in a question
        self.text = ""                # after the call: what the model would read
        self.images: list = []        # ... the images in it, as bytes
        self.raw = None               # ... and the result as the agent gave it, for the quarantine
        self.gate_first = False       # an event that is both: gate the call, then judge the content it carries


class Decision:
    def __init__(self, action: str, notice: str = "", reason: str = "", topic: str = "", why: str = ""):
        self.action = action          # "replace": put notice in place of the result; "ask": hold the call for approval
        self.notice = notice
        self.reason = reason          # ask: the whole explanation, for a front end that shows it
        self.topic = topic            # ask: in two or three words what is at stake
        self.why = why                # ask: what in this call set the question off


def _evidence(v: dict) -> dict:
    return {"score": v.get("score"), "reasons": v.get("reasons") or None, "flags": v.get("flags") or None,
            "signals": v.get("signals") or None, "n_chunks": v.get("n_chunks"), "tokens": v.get("tokens")}


def _existing(cfg, paths: list[str]) -> list[str]:
    """Tracked files that are really there. A name the command did not create (an option value
    taken for a file name) or a download that has since been deleted is not outside content."""
    return list(paths) if cfg.track_missing_files else [p for p in paths if os.path.lexists(p)]


# ---- the question, written into the command ---------------------------------------------------------
# The reason that goes out with "ask" is shown by a terminal. Other front ends (the approval card
# of the mobile app) show the command and nothing else, cut to one line. So for a shell command
# the explanation is also put where every front end shows it: as comment lines at the top of the
# command. They do nothing in a shell; the first is kept short enough to be read on that card.
OWN_LINE = "# jevguard: "


def one_line(text, limit: int) -> str:
    """Fit for one comment line: a line break in it would end the comment and start a command."""
    return " ".join("".join(c if c.isprintable() else " " for c in str(text)).split())[:limit]


def without_own_lines(command: str) -> str:
    """The command without the comment lines on top of it. Once approved it runs with them, and
    the guard sees it again with its result; what a comment says is no part of what ran. Whoever
    wrote such a line, it is a comment to the shell, so leaving it out changes nothing."""
    lines = command.split("\n")
    while len(lines) > 1 and lines[0].startswith(OWN_LINE.rstrip()):
        lines.pop(0)
    return "\n".join(lines)


def with_question(command: str, decision: Decision, says: str = "", who: str = "Claude") -> str:
    """The command under comment lines that say why it is asked about."""
    lines = [OWN_LINE + decision.topic, OWN_LINE + "why: " + one_line(decision.why, 300)]
    said = one_line(says, 140)
    if said:
        lines.append(f"{OWN_LINE}{who} says: {said}")  # its own words, not checked
    return "\n".join([*lines, command])


def _purpose(call: Call) -> str:
    """What the agent said the call is for, to go into the question. A long command says little
    to the person asked; this one sentence is the agent's own claim, and is labelled as that."""
    said = " ".join(str(call.tool_input.get("description") or "").split())[:140]
    return f' {call.who} describes the call as: "{said}" (its own words, not checked).' if said else ""


# ---- after a call: the result ------------------------------------------------------------------------
def after(call: Call, cfg, ctx: dict) -> Decision | None:
    from . import firstparty, provenance, toolio
    tool, tool_input, sid, cwd, text, images = call.tool, call.tool_input, call.session, call.cwd, call.text, call.images
    try:
        session = store.session(cfg, sid)
    except (ValueError, OSError):
        session = None  # which files this session downloaded is not known
    mode = provenance.classify(tool, tool_input, cfg, cwd, _existing(cfg, (session or {}).get("paths", [])), text)
    if session is None and mode in ("local", "warn"):
        mode = "external"  # it may be one of them
    ctx["mode"] = mode  # what the error path needs to know if anything below fails
    if mode is None:
        return None
    if mode in OUTSIDE:
        if not session:
            store.prune_sessions(cfg)  # first outside content of a session: drop old session files
        paths = _existing(cfg, provenance.saved_paths(str(tool_input.get("command") or ""), cwd, cfg.track_clones)) if tool == "Bash" else []
        store.session_update(cfg, sid, paths=paths, external=True)
    elif not cfg.scan_local:
        return None
    if toolio.words(text) < cfg.min_words and not images:
        return None
    digest = store.content_hash(text, images)
    base = {"event": "scan", "tool": tool, "mode": mode, "session": sid, **call.ids, "cwd": cwd, "chars": len(text),
            "images": len(images) or None, "sha256": digest[:16], "guard_mode": cfg.mode}
    if digest in store.released(cfg):
        store.audit(cfg, **base, action="passed-released")
        return None
    enforce = cfg.mode == "block" and mode not in ("warn", "trusted")
    # Outside content the scan could not vouch for (the API failed, part of it was unreadable) is
    # withheld when the owner chose on_error = closed.
    withhold_unscanned = enforce and cfg.on_error == "closed" and mode in ("external", "own")
    firstparty.use(cfg)

    def keep(verdict: dict) -> str:
        return store.quarantine(cfg, tool, tool_input, call.raw, verdict, digest, text, images)

    def unavailable(error: str, verdict: dict | None = None, **extra) -> Decision | None:
        store.audit(cfg, **base, action="blocked-unavailable" if withhold_unscanned else "passed-unscanned",
                    verdict="unavailable", error=error[:200], **(_evidence(verdict) if verdict else {}), **extra)
        if mode in OUTSIDE:
            store.session_update(cfg, sid, flagged="unscanned")
        if withhold_unscanned:
            return Decision("replace", firstparty.notice(tool, {"verdict": "unavailable", "reasons": ["firewall unreachable"]}))
        return None

    key = config.read_key(cfg)
    blocked_by = "no API key" if not key else store.scanner_available(cfg)
    if blocked_by:
        return unavailable(blocked_by)
    from . import scanner  # the scoring client and extraction code: loaded only when something is scanned
    t0 = time.perf_counter()
    sc = scanner.Scanner(cfg, key)
    verdict, err = sc.scan(text, images)
    ms = round((time.perf_counter() - t0) * 1000)
    store.usage_add(cfg, tokens=verdict.get("tokens") or 0, outage=bool(err is not None and err.outage))
    v = verdict.get("verdict")
    if err is not None and v != "injection":  # nothing conclusive found before the failure
        return unavailable(str(err), verdict, partial_verdict=v, outage=err.outage, ms=ms)
    # Local content and what gh returns about the owner's own repositories are withheld only from
    # a higher score up; between the policy level and that one they are logged as flagged.
    # What gh prints can carry local content (a request body read from a file comes back in the
    # reply, --dry-run prints the text of local commits), so where local output is scanned at all,
    # own-repository output is never given the more lenient of the two levels.
    own_block = min(cfg.own_repos_block, cfg.local_block) if cfg.scan_local else cfg.own_repos_block
    block_at = {"local": cfg.local_block, "own": own_block}.get(mode)
    if v == "injection" and block_at is not None and (verdict.get("score") or 0) < block_at:
        verdict, v = dict(verdict, verdict="suspicious"), "suspicious"
    incomplete = sorted(set(verdict.get("flags") or []) & scanner.INCOMPLETE)
    rec = dict(base, verdict=v, **_evidence(verdict), ms=ms, policy=sc.policy_id, complete=not incomplete,
               block_at=block_at, error=f"later part not scanned: {err}"[:200] if err is not None else None)
    if v == "injection":
        store.session_update(cfg, sid, flagged="injection")
        # Kept in log mode too: it is what the owner reads to judge a would-be block.
        qid = keep(verdict)
        store.audit(cfg, **rec, action="blocked" if enforce else "would-block", quarantine_id=qid)
        return Decision("replace", firstparty.notice(tool, verdict, qid, str(store.released_copy(cfg, qid)))) if enforce else None
    if incomplete:  # an image without OCR, undecodable data, more images than the limit
        if mode in OUTSIDE:
            store.session_update(cfg, sid, flagged="unscanned")
        if withhold_unscanned:
            held = dict(verdict, verdict="incomplete")
            qid = keep(held)
            store.audit(cfg, **rec, action="blocked-incomplete", quarantine_id=qid)
            return Decision("replace", firstparty.notice(tool, held, qid, str(store.released_copy(cfg, qid))))
    store.audit(cfg, **rec, action="flagged" if v == "suspicious" else "passed")
    return None


# ---- before a call: the gate -------------------------------------------------------------------------
def before(call: Call, cfg) -> Decision | None:
    from . import gate
    tool, tool_input, sid, cwd = call.tool, call.tool_input, call.session, call.cwd
    detail = str(tool_input.get("command") or tool_input.get("url") or tool_input.get("file_path")
                 or tool_input.get("path") or "")[:160]
    ids = {"event": "gate", "tool": tool, "session": sid, **call.ids, "cwd": cwd, "detail": detail}
    if cfg.protect_guard:
        why = gate.guard_change(tool, tool_input, cfg, cwd)
        if why:
            store.audit(cfg, **ids, why=why, taint="guard", action="asked")
            return Decision("ask", reason=f"asking because {why}.{_purpose(call)} Approve only if you expect this "
                            "session to be changing the guard or Claude Code's settings right now; you do not "
                            "need to review the rest of the command.", topic="CHANGES THE GUARD", why=why)
    if cfg.gate == "off":
        return None
    why = gate.risky(tool, tool_input, cwd)
    if not why:
        return None
    try:
        s = store.session(cfg, sid)
    except (ValueError, OSError):
        s = store.UNREADABLE_SESSION
    taint = "flagged" if s.get("flagged") else "external" if s.get("external") else ""
    if not taint:
        return None
    ask = cfg.gate == "ask-external" or (cfg.gate == "ask-flagged" and taint == "flagged")
    store.audit(cfg, **ids, why=why, taint=taint, taint_reason=s.get("flagged_reason"),
                action="asked" if ask else "would-ask")
    if not ask:
        return None
    seen = ("a tool result scored as a prompt injection or passed without a full scan" if taint == "flagged"
            else "content from outside was read")
    return Decision("ask", reason=f"asking because earlier in this session {seen}, and this call {why}.{_purpose(call)}",
                    topic="RISKY AFTER OUTSIDE CONTENT", why=f"{why}, and earlier in this session {seen}")


# ---- when the guard itself fails ---------------------------------------------------------------------
def after_error(phase: str, call: Call | None, cfg, ctx: dict, exc: BaseException) -> Decision | None:
    """What a guard error costs. Before a call: the check did not happen, so wherever the guard
    is set to ask, the call is asked about (also when its settings could not be read). After a
    call: outside content is withheld if the owner chose on_error = closed; when the failure
    came before the origin was known, and it still cannot be worked out, the result is withheld
    rather than assumed to be local."""
    if phase == "before":
        if cfg is None or cfg.protect_guard or cfg.gate.startswith("ask"):
            return Decision("ask", reason=f"the guard hit an error and could not check this call ({type(exc).__name__}).",
                            topic="GUARD ERROR, CALL NOT CHECKED", why=f"the guard failed with {type(exc).__name__}")
        return None
    if cfg is None or cfg.mode != "block" or cfg.on_error != "closed" or phase != "after" or call is None:
        return None
    from . import firstparty, provenance
    mode = ctx.get("mode", UNKNOWN)
    if mode == UNKNOWN:
        try:
            paths = _existing(cfg, store.session(cfg, call.session).get("paths", []))
            mode = provenance.classify(call.tool, call.tool_input, cfg, call.cwd, paths, call.text)
        except Exception:
            mode = "external"
    if mode not in ("external", "own"):
        return None
    try:
        firstparty.use(cfg)
    except Exception:
        pass  # an unsealed notice is still a notice; a later scan will score it instead of removing it
    return Decision("replace", firstparty.notice(call.tool, {"verdict": "unavailable", "reasons": ["firewall plugin error"]}))
