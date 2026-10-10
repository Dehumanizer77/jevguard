"""What to do with a tool call, and with what it returned, whichever agent it belongs to.

The engine speaks one vocabulary for tools, the one this guard started with:

    Bash        tool_input: command, description
    Read, Grep  tool_input: file_path or path
    WebFetch    tool_input: url
    WebSearch
    Write, Edit, NotebookEdit   tool_input: file_path
    Monitor     tool_input: command; what it prints goes to the model line by line, as
                notifications, and never comes back as a result a hook could look at
    mcp__<server>__<tool>       anything that brings content in from outside

An adapter (jevguard/agents) turns its agent's tool calls into a Call in that vocabulary and a
Decision back into what its agent understands. The engine knows nothing about any agent: not
the names of its tools, not the shape of their results, not how it is told to ask or to replace.

A command sent to the background returns nothing at once. Its output reaches the model later,
by one of three routes, and is still that command's output:

    a file the agent reads   the adapter names the file (Call.later_paths) and the task
                             (Call.later_ids) when the command starts; if the command is outside
                             content, the file is tracked like a download
    another tool             the adapter hands that tool's result over as a Bash result of the
                             command that printed it, with the tasks it is about (Call.task_ids)
    notifications            nothing to scan; see Monitor
"""

from __future__ import annotations

import os
import re
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
        self.later_ids: list = []     # the call sent a command to the background: the tasks it started
        self.later_paths: list = []   # ... and the files their output is written to
        self.task_ids: list = []      # the result is the output of these background tasks
        self.replaceable = True       # False: the agent lets nothing be put in place of this result (a failed call)


class Decision:
    def __init__(self, action: str, notice: str = "", reason: str = "", topic: str = "", why: str = ""):
        self.action = action          # "replace": put notice in place of the result; "ask": hold the call for approval;
        #                               "warn": the result cannot be replaced, notice is all that can be said beside it
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


# ---- output that comes later -------------------------------------------------------------------------
_TASK_OUTPUT = re.compile(r"(?:~|/)[^\s\"'<>|;&()$`\\]*/tasks/([A-Za-z0-9_-]{1,80})\.output")


def _task_outputs(tool_input: dict, cwd: str, tasks: list) -> list[str]:
    """The output files of this session's outside background tasks that the call names. Where the
    adapter could work out the file when the command started, it is tracked already; this is for
    where it could not (the directory an agent keeps such files in is its own business, the name
    `tasks/<id>.output` is what the model is told)."""
    if not tasks:
        return []
    from .shell import canonical
    found = []
    for key in ("command", "file_path", "path"):
        value = tool_input.get(key)
        for m in _TASK_OUTPUT.finditer(value) if isinstance(value, str) else ():
            if m.group(1) in tasks:
                found.append(canonical(m.group(0), cwd))
    return found


def _stream_origin(call: Call, cfg) -> str:
    """Where what a Monitor prints would come from, its command read like any shell command:
    "external", "own" (one gh command that names one of the owner's repositories), or "" for a
    command that brings nothing in from outside."""
    from . import provenance
    ws = call.tool_input.get("ws")
    if ws is not None:
        # A Monitor on a WebSocket: every frame the server sends becomes a notification. There is
        # no command to read; the address says where it comes from, as for a fetch.
        try:
            url = str(ws.get("url") if isinstance(ws, dict) else ws)
            host = provenance._URL.match(url)
            return "" if host and provenance.private_host(host.group(1)) and not cfg.scan_private_hosts else "external"
        except Exception:
            return "external"
    try:
        session = store.session(cfg, call.session)
    except (ValueError, OSError):
        return "external"  # which files this session downloaded is not known: it may print one of them
    try:
        paths = [*session.get("paths", []), *_task_outputs(call.tool_input, call.cwd, list(session.get("tasks", [])))]
        mode = provenance.classify("Bash", call.tool_input, cfg, call.cwd, _existing(cfg, paths), "")
    except Exception:
        return "external"  # it could not be worked out, and after the monitor has started nothing can be done
    return mode if mode in ("external", "own") else ""


# ---- counting and recording --------------------------------------------------------------------------
def _record(ctx: dict | None, step, *args, **kwargs):
    """Run one step of bookkeeping: the session's marks, the day's usage, the quarantine, the log,
    the seal key. None of these is part of a verdict, or of the policy that follows from one, so
    none of them may change what the model is given or whether the owner is asked. A step that
    fails (a full disk, a damaged or read-only state directory, a sandbox) is noted in
    ctx["unrecorded"] for the caller to report, and the work goes on without it.

    Twice a failure here did decide the outcome: first the quarantine and the log, then the usage
    counter, each letting a result through that had just scored as an injection (on_error = open
    is for a scan that failed, and those scans had not). So every write goes through here, not
    the ones that have failed so far."""
    try:
        return step(*args, **kwargs)
    except Exception as exc:
        if ctx is not None:
            ctx.setdefault("unrecorded", []).append(
                f"{getattr(step, '__name__', 'step')}: {type(exc).__name__}: {exc}"[:200])
        return None


# ---- after a call: the result ------------------------------------------------------------------------
def after(call: Call, cfg, ctx: dict) -> Decision | None:
    from . import firstparty, provenance, toolio
    tool, tool_input, sid, cwd, text, images = call.tool, call.tool_input, call.session, call.cwd, call.text, call.images
    try:
        session = store.session(cfg, sid)
    except (ValueError, OSError):
        session = None  # which files this session downloaded is not known
    tasks = list((session or {}).get("tasks", []))
    seen = _task_outputs(tool_input, cwd, tasks)
    mode = provenance.classify(tool, tool_input, cfg, cwd, _existing(cfg, [*(session or {}).get("paths", []), *seen]), text)
    if mode in ("local", "warn") and any(str(t) in tasks for t in call.task_ids):
        mode = "external"  # the output of a command that was outside content when it was started
    if session is None and mode in ("local", "warn"):
        mode = "external"  # it may be one of them
    ctx["mode"] = mode  # what the error path needs to know if anything below fails
    if mode is None:
        return None
    def record(step, *args, **kwargs):  # see _record: nothing that is only written down decides anything below
        return _record(ctx, step, *args, **kwargs)

    if mode in OUTSIDE:
        if not session:
            store.prune_sessions(cfg)  # first outside content of a session: drop old session files
        paths = _existing(cfg, provenance.saved_paths(str(tool_input.get("command") or ""), cwd, cfg.track_clones)) if tool == "Bash" else []
        # What a background command prints is this command's output, wherever it turns up later.
        record(store.session_update, cfg, sid, paths=[*paths, *seen, *call.later_paths], external=True, tasks=call.later_ids)
    elif not cfg.scan_local:
        return None
    if toolio.words(text) < cfg.min_words and not images:
        return None
    digest = store.content_hash(text, images)
    base = {"event": "scan", "tool": tool, "mode": mode, "session": sid, **call.ids, "cwd": cwd, "chars": len(text),
            "images": len(images) or None, "sha256": digest[:16], "guard_mode": cfg.mode}
    if digest in store.released(cfg):
        record(store.audit, cfg, **base, action="passed-released")
        return None
    enforce = cfg.mode == "block" and mode not in ("warn", "trusted")
    # Outside content the scan could not vouch for (the API failed, part of it was unreadable) is
    # withheld when the owner chose on_error = closed.
    withhold_unscanned = enforce and cfg.on_error == "closed" and mode in ("external", "own") and call.replaceable
    record(firstparty.use, cfg)  # without the seal key a notice goes out unsealed; it is a notice all the same

    def keep(verdict: dict) -> str:
        return record(store.quarantine, cfg, tool, tool_input, call.raw, verdict, digest, text, images) or ""

    def notice(verdict: dict, qid: str = "") -> str:
        return firstparty.notice(tool, verdict, qid, str(store.released_copy(cfg, qid)) if qid else "")

    def unavailable(error: str, verdict: dict | None = None, **extra) -> Decision | None:
        ctx["scan"] = "failed"  # for a wrapper: this output was not judged, the hook after the call is still to look at it
        record(store.audit, cfg, **base, action="blocked-unavailable" if withhold_unscanned else "passed-unscanned",
               verdict="unavailable", error=error[:200], **(_evidence(verdict) if verdict else {}), **extra)
        if mode in OUTSIDE:
            record(store.session_update, cfg, sid, flagged="unscanned")
        if withhold_unscanned:
            return Decision("replace", notice({"verdict": "unavailable", "reasons": ["firewall unreachable"]}))
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
    # The scan has returned. From here on there is the verdict, the owner's policy for it, and
    # writing down what happened: the first two decide, the third goes through record().
    record(store.usage_add, cfg, tokens=verdict.get("tokens") or 0, outage=bool(err is not None and err.outage))
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
        record(store.session_update, cfg, sid, flagged="injection")
        # Kept in log mode too: it is what the owner reads to judge a would-be block.
        qid = keep(verdict)
        if enforce and not call.replaceable:
            # The output of a failed call, in an agent whose hook for that can add a remark and
            # nothing else. The model has it; the log says so, and the model is told what it is.
            record(store.audit, cfg, **rec, action="not-withheld", quarantine_id=qid or None)
            return Decision("warn", firstparty.warning(tool, verdict, qid))
        record(store.audit, cfg, **rec, action="blocked" if enforce else "would-block", quarantine_id=qid or None)
        return Decision("replace", notice(verdict, qid)) if enforce else None
    if incomplete:  # an image without OCR, undecodable data, more images than the limit
        ctx["scan"] = "failed"
        if mode in OUTSIDE:
            record(store.session_update, cfg, sid, flagged="unscanned")
        if withhold_unscanned:
            held = dict(verdict, verdict="incomplete")
            qid = keep(held)
            record(store.audit, cfg, **rec, action="blocked-incomplete", quarantine_id=qid or None)
            return Decision("replace", notice(held, qid))
    record(store.audit, cfg, **rec, action="flagged" if v == "suspicious" else "passed")
    return None


# ---- before a call: the gate -------------------------------------------------------------------------
def before(call: Call, cfg, ctx: dict | None = None) -> Decision | None:
    from . import gate
    tool, tool_input, sid, cwd = call.tool, call.tool_input, call.session, call.cwd
    detail = str(tool_input.get("command") or tool_input.get("url") or tool_input.get("file_path")
                 or tool_input.get("path") or "")[:160]
    ids = {"event": "gate", "tool": tool, "session": sid, **call.ids, "cwd": cwd, "detail": detail}
    read_as = "Bash" if tool == "Monitor" else tool  # a monitor runs a shell command, whatever becomes of its output

    def record(step, *args, **kwargs):  # see _record: whether the owner is asked does not hang on a line in the log
        return _record(ctx, step, *args, **kwargs)

    if cfg.protect_guard:
        why = gate.guard_change(read_as, tool_input, cfg, cwd)
        if why:
            record(store.audit, cfg, **ids, why=why, taint="guard", action="asked")
            return Decision("ask", reason=f"asking because {why}.{_purpose(call)} Approve only if you expect this "
                            "session to be changing the guard or Claude Code's settings right now; you do not "
                            "need to review the rest of the command.", topic="CHANGES THE GUARD", why=why)
    origin = _stream_origin(call, cfg) if tool == "Monitor" else ""
    if origin == "own":
        # The owner's choice (2026-10-10): watching one of his own repositories is recorded and not
        # asked about. It is what own_repos stands for everywhere else, content he vouches for more
        # than a stranger's; here it also goes unscanned, and the log says so. Only the one form
        # counts that counts elsewhere: a single gh command naming the repository, nothing around it.
        record(store.audit, cfg, **ids, taint="unscanned", action="logged",
               why="its output goes to the model as notifications, unscanned; the command is one gh command on an own repository")
        record(store.session_update, cfg, sid, external=True)
    elif origin:
        # What it prints goes to the model as notifications. No hook sees those, so nothing of it
        # can be scanned or withheld afterwards; the one place to stop it is here. This is not
        # the gate (a risky action) and not on_error (a scan that failed): it is outside content
        # on a road with no check on it, and in block mode the owner is asked before it starts.
        why = "its output would go to the model as notifications, which cannot be scanned, and the command reads from outside"
        record(store.audit, cfg, **ids, why=why, taint="unscanned", action="asked" if cfg.mode == "block" else "would-ask")
        record(store.session_update, cfg, sid, external=True, flagged="unscanned")
        if cfg.mode == "block":
            return Decision("ask", reason=f"asking because {why}.{_purpose(call)} Run it as an ordinary command, or in "
                            "the background and read its output file, and the guard scans what it prints.",
                            topic="OUTPUT CANNOT BE SCANNED", why=why)
    if cfg.gate == "off":
        return None
    why = gate.risky(read_as, tool_input, cwd)
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
    record(store.audit, cfg, **ids, why=why, taint=taint, taint_reason=s.get("flagged_reason"),
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
    if not call.replaceable:
        return None  # nothing can be put in its place, so nothing is claimed to have been
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
