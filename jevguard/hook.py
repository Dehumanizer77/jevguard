"""Claude Code hook entry point. Reads the hook input on stdin and, for PostToolUse, scans the
tool result; for PreToolUse, checks a risky action against what the session has read.

In "log" mode nothing is printed, so the hook can run with `async: true` and cost no time.
In "block" mode a result that scores as an injection is replaced whole by a short notice
(updatedToolOutput). Text is never added to a result: a warning inside it is one more
instruction-like passage for the model to read.
"""

from __future__ import annotations

import json
import os
import signal
import sys
import time

from . import config, gate, provenance, scanner, store, toolio
from .core.trusted import _NOTE as NOTE  # the exact sentence core/trusted.py removes before scoring

_CLASSIFIER_NOTE = ("jevguard withheld a tool result in this session as a likely prompt injection. Actions that "
                    "send data out, publish, or change startup and configuration files need the user's approval.")


def notice(tool: str, verdict: dict, qid: str = "") -> str:
    """The block notice, in the upstream format so that a later scan recognises and removes it."""
    source = "".join(c if c.isalnum() or c in "_:.-" else "_" for c in tool)[:60]
    return json.dumps({
        "firewall": "blocked", "verdict": verdict.get("verdict", "unavailable"),
        "score": verdict.get("score"), "source": source,
        "reasons": [str(r)[:80] for r in (verdict.get("reasons") or [])][:5],
        "quarantine_id": qid, "note": NOTE}, ensure_ascii=False)


def _replace(tool: str, resp, text: str) -> dict:
    return {"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                   "updatedToolOutput": toolio.replaced(tool, resp, text),
                                   "classifierContext": _CLASSIFIER_NOTE}}


def _evidence(v: dict) -> dict:
    return {"score": v.get("score"), "reasons": v.get("reasons") or None, "flags": v.get("flags") or None,
            "signals": v.get("signals") or None, "n_chunks": v.get("n_chunks"), "tokens": v.get("tokens")}


def post_tool_use(d: dict, cfg) -> dict | None:
    tool = str(d.get("tool_name") or "")
    tool_input = d.get("tool_input") if isinstance(d.get("tool_input"), dict) else {}
    resp = d.get("tool_response")
    sid, cwd = str(d.get("session_id") or ""), str(d.get("cwd") or "")
    mode = provenance.classify(tool, tool_input, cfg, cwd, store.session(cfg, sid).get("paths", []))
    if mode is None:
        return None
    if mode == "external":
        if not store.session(cfg, sid):
            store.prune_sessions(cfg)  # first outside content of a session: drop old session files
        paths = provenance.saved_paths(str(tool_input.get("command") or ""), cwd, cfg.track_clones) if tool == "Bash" else []
        store.session_update(cfg, sid, paths=paths, external=True)
    elif not cfg.scan_local:
        return None
    text, images = toolio.text_of(tool, resp)
    if scanner.words(text) < cfg.min_words and not images:
        return None
    digest = store.content_hash(text, images)
    base = {"event": "scan", "tool": tool, "mode": mode, "session": sid, "tool_use_id": d.get("tool_use_id"),
            "agent": d.get("agent_type"), "cwd": cwd, "chars": len(text), "images": len(images) or None,
            "sha256": digest[:16], "guard_mode": cfg.mode}
    if digest in store.released(cfg):
        store.audit(cfg, **base, action="passed-released")
        return None
    enforce = cfg.mode == "block" and mode != "warn"
    withhold_unscanned = enforce and cfg.on_error == "closed" and mode == "external"

    def unavailable(error: str, verdict: dict | None = None, **extra) -> dict | None:
        store.audit(cfg, **base, action="blocked-unavailable" if withhold_unscanned else "passed-unscanned",
                    verdict="unavailable", error=error[:200], **(_evidence(verdict) if verdict else {}), **extra)
        if mode == "external":
            store.session_update(cfg, sid, flagged="unscanned")
        if withhold_unscanned:
            return _replace(tool, resp, notice(tool, {"verdict": "unavailable", "reasons": ["firewall unreachable"]}))
        return None

    key = config.read_key(cfg)
    blocked_by = "no API key" if not key else store.scanner_available(cfg)
    if blocked_by:
        return unavailable(blocked_by)
    t0 = time.perf_counter()
    sc = scanner.Scanner(cfg, key)
    verdict, err = sc.scan(text, images)
    ms = round((time.perf_counter() - t0) * 1000)
    store.usage_add(cfg, tokens=verdict.get("tokens") or 0, outage=bool(err is not None and err.outage))
    v = verdict.get("verdict")
    if err is not None and v != "injection":  # nothing conclusive found before the failure
        return unavailable(str(err), verdict, partial_verdict=v, outage=err.outage, ms=ms)
    if v == "injection" and mode == "local" and (verdict.get("score") or 0) < cfg.local_block:
        verdict, v = dict(verdict, verdict="suspicious"), "suspicious"  # below the local level
    rec = dict(base, verdict=v, **_evidence(verdict), ms=ms, policy=sc.policy_id,
               complete=not (set(verdict.get("flags") or []) & scanner.INCOMPLETE),
               error=f"later part not scanned: {err}"[:200] if err is not None else None)
    if v == "injection":
        store.session_update(cfg, sid, flagged="injection")
        # Kept in log mode too: it is what the owner reads to judge a would-be block.
        qid = store.quarantine(cfg, tool, tool_input, resp, verdict, digest)
        store.audit(cfg, **rec, action="blocked" if enforce else "would-block", quarantine_id=qid)
        return _replace(tool, resp, notice(tool, verdict, qid)) if enforce else None
    store.audit(cfg, **rec, action="flagged" if v == "suspicious" else "passed")
    return None


def pre_tool_use(d: dict, cfg) -> dict | None:
    if cfg.gate == "off":
        return None
    tool = str(d.get("tool_name") or "")
    tool_input = d.get("tool_input") if isinstance(d.get("tool_input"), dict) else {}
    why = gate.risky(tool, tool_input)
    if not why:
        return None
    sid = str(d.get("session_id") or "")
    s = store.session(cfg, sid)
    taint = "flagged" if s.get("flagged") else "external" if s.get("external") else ""
    if not taint:
        return None
    ask = cfg.gate == "ask-external" or (cfg.gate == "ask-flagged" and taint == "flagged")
    detail = str(tool_input.get("command") or tool_input.get("url") or tool_input.get("file_path") or "")[:160]
    store.audit(cfg, event="gate", tool=tool, session=sid, tool_use_id=d.get("tool_use_id"),
                agent=d.get("agent_type"), cwd=d.get("cwd"), why=why, taint=taint,
                taint_reason=s.get("flagged_reason"), detail=detail, action="asked" if ask else "would-ask")
    if not ask:
        return None
    seen = ("a tool result scored as a prompt injection or passed unscanned" if taint == "flagged"
            else "content from outside was read")
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                   "permissionDecisionReason": f"jevguard: earlier in this session {seen}, and this call {why}."}}


def _on_alarm(*_):
    raise TimeoutError("jevguard watchdog")


def _fail_closed(d: dict, cfg) -> dict | None:
    """After a guard error: withhold outside content if the owner chose on_error = closed."""
    if cfg is None or cfg.mode != "block" or cfg.on_error != "closed" or d.get("hook_event_name") != "PostToolUse":
        return None
    tool = str(d.get("tool_name") or "")
    tool_input = d.get("tool_input") if isinstance(d.get("tool_input"), dict) else {}
    if provenance.classify(tool, tool_input, cfg, str(d.get("cwd") or ""), []) != "external":
        return None
    return _replace(tool, d.get("tool_response"),
                    notice(tool, {"verdict": "unavailable", "reasons": ["firewall plugin error"]}))


def main() -> None:
    out, d, cfg = None, {}, None
    try:
        d = json.loads(sys.stdin.read() or "{}")
        cfg = config.load()
        signal.signal(signal.SIGALRM, _on_alarm)
        signal.alarm(int(cfg.deadline) + 8)
        event = d.get("hook_event_name")
        if event == "PostToolUse":
            out = post_tool_use(d, cfg)
        elif event == "PreToolUse":
            out = pre_tool_use(d, cfg)
    except BaseException as exc:  # a guard bug must not take the session down
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        print(f"jevguard: {type(exc).__name__}: {exc}", file=sys.stderr)
        try:
            signal.alarm(0)
            out = _fail_closed(d, cfg)
            store.audit(cfg or config.load(), event="error", tool=d.get("tool_name"), session=d.get("session_id"),
                        action="blocked-error" if out else "passed-error",
                        error=f"{type(exc).__name__}: {exc}"[:300])
        except Exception:
            pass
    if out is not None:
        sys.stdout.write(json.dumps(out, ensure_ascii=False))
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)  # do not wait for scoring threads that are past the deadline
