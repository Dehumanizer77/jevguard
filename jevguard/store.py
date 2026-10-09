"""Files the guard keeps: scan log, quarantine, release list, per-session state, daily usage.

Several hook processes run at once when Claude makes parallel tool calls, so every
read-modify-write goes through an exclusive lock and the log is appended in single writes.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

_MAX_LOG = 20 * 1024 * 1024
_SESSION_ID = re.compile(r"[A-Za-z0-9_-]{1,80}")
QID = re.compile(r"fw-\d{8}-[0-9a-f]{6}")


def _private_dir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True, mode=0o700)
    return p


@contextmanager
def _locked(path: Path):
    """Exclusive lock on path; yields the parsed JSON object and writes it back on exit."""
    _private_dir(path.parent)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        with os.fdopen(os.dup(fd), "r+") as f:
            raw = f.read()
            try:
                data = json.loads(raw) if raw.strip() else {}
            except ValueError:
                data = {}
            yield data
            f.seek(0)
            f.truncate()
            json.dump(data, f)
    finally:
        os.close(fd)


def audit(cfg, **rec) -> None:
    """One JSON line per scan. Never the content."""
    path = cfg.scan_log
    _private_dir(path.parent)
    if path.exists() and path.stat().st_size > _MAX_LOG:
        path.replace(path.with_suffix(".jsonl.1"))
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **{k: v for k, v in rec.items() if v is not None}}
    line = (json.dumps(rec, ensure_ascii=False) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)


def content_hash(text: str, images: list) -> str:
    """Identity of what the model would see, for the owner's release list."""
    h = hashlib.sha256(text.encode("utf-8", "ignore"))
    for img in images:
        h.update(b"\0" + hashlib.sha256(img).digest())
    return h.hexdigest()


def quarantine(cfg, tool: str, tool_input: dict, raw, verdict: dict, digest: str) -> str:
    qid = f"fw-{time.strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}"
    p = _private_dir(cfg.quarantine_dir) / f"{qid}.json"
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"tool": tool, "tool_input": tool_input, "verdict": verdict,
                   "content_sha256": digest, "raw": raw}, f, ensure_ascii=False)
    return qid


def released(cfg) -> frozenset:
    """Content hashes the owner released after reading the quarantined original."""
    try:
        lines = cfg.released_file.read_text().splitlines()
    except OSError:
        return frozenset()
    return frozenset(l.split()[0] for l in lines if l.strip() and not l.startswith("#"))


def release(cfg, qid: str) -> str:
    rec = json.loads((cfg.quarantine_dir / f"{qid}.json").read_text())
    line = f"{rec['content_sha256']} {qid} {rec.get('tool', '?')} released {time.strftime('%Y-%m-%d')}\n"
    _private_dir(cfg.released_file.parent)
    fd = os.open(cfg.released_file, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, line.encode())
    finally:
        os.close(fd)
    return rec["content_sha256"]


# ---- per-session state: files saved by fetching commands, and what the session has seen ----

def _session_file(cfg, session_id: str) -> Path:
    sid = session_id if _SESSION_ID.fullmatch(session_id or "") else "unknown"
    return cfg.sessions_dir / f"{sid}.json"


def session(cfg, session_id: str) -> dict:
    try:
        return json.loads(_session_file(cfg, session_id).read_text())
    except (OSError, ValueError):
        return {}


def session_update(cfg, session_id: str, *, paths: list = (), external: bool = False,
                   flagged: str = "") -> None:
    with _locked(_session_file(cfg, session_id)) as s:
        if paths:
            s["paths"] = list(dict.fromkeys([*s.get("paths", []), *paths]))[-500:]
        if external:
            s["external"] = s.get("external", 0) + 1
        if flagged:
            s["flagged"] = s.get("flagged", 0) + 1
            s["flagged_reason"] = flagged


def prune_sessions(cfg, days: int = 14) -> None:
    cutoff = time.time() - days * 86400
    try:
        for p in cfg.sessions_dir.iterdir():
            if p.stat().st_mtime < cutoff:
                p.unlink(missing_ok=True)
    except OSError:
        pass


# ---- daily token budget and the pause after an API failure ----

def usage(cfg) -> dict:
    try:
        return json.loads(cfg.usage_file.read_text())
    except (OSError, ValueError):
        return {}


def scanner_available(cfg) -> str:
    """Empty when scanning may go ahead, else the reason it may not."""
    u = usage(cfg)
    if time.time() < u.get("down_until", 0):
        return "scanner paused after a failure"
    if u.get("day") == time.strftime("%Y-%m-%d") and u.get("tokens", 0) >= cfg.daily_token_budget:
        return "daily token budget reached"
    return ""


def usage_add(cfg, tokens: int = 0, outage: bool = False) -> None:
    with _locked(cfg.usage_file) as u:
        day = time.strftime("%Y-%m-%d")
        if u.get("day") != day:
            u.update(day=day, tokens=0, scans=0)
        u["tokens"] = u.get("tokens", 0) + int(tokens)
        u["scans"] = u.get("scans", 0) + 1
        if outage:
            u["down_until"] = time.time() + cfg.breaker_seconds
