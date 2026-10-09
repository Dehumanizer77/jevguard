"""Files the guard keeps: scan log, quarantine, release list, per-session state, daily usage.

Several hook processes run at once when Claude makes parallel tool calls, so every
read-modify-write goes through an exclusive lock and the log is appended in single writes.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import time
from pathlib import Path

_MAX_LOG = 20 * 1024 * 1024
_SESSION_ID = re.compile(r"[A-Za-z0-9_-]{1,80}")
QID = re.compile(r"fw-\d{8}-[0-9a-f]{6}")


def _private_dir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True, mode=0o700)
    return p


class _locked:
    """Read-modify-write of a JSON file: `with _locked(path) as data`. Writers queue on a lock
    file beside it, and the file itself is replaced in one step, so a reader, which takes no
    lock, sees either the old content or the new and never a half-written one."""

    def __init__(self, path: Path, if_unreadable: dict | None = None):
        self.path, self.if_unreadable = path, if_unreadable or {}

    def __enter__(self) -> dict:
        _private_dir(self.path.parent)
        self.lock = os.open(f"{self.path}.lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX)
            try:
                self.data = json.loads(self.path.read_text())
                if not isinstance(self.data, dict):
                    raise ValueError("not an object")
            except FileNotFoundError:
                self.data = {}
            except ValueError:
                self.data = dict(self.if_unreadable)
        except BaseException:
            os.close(self.lock)
            raise
        return self.data

    def __exit__(self, exc_type, *_):
        try:
            if exc_type is None:
                tmp = f"{self.path}.{os.getpid()}.tmp"
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w") as f:
                    json.dump(self.data, f)
                os.replace(tmp, self.path)
        finally:
            os.close(self.lock)


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
    import hashlib
    h = hashlib.sha256(text.encode("utf-8", "ignore"))
    for img in images:
        h.update(b"\0" + hashlib.sha256(img).digest())
    return h.hexdigest()


def quarantine(cfg, tool: str, tool_input: dict, raw, verdict: dict, digest: str) -> str:
    qid = f"fw-{time.strftime('%Y%m%d')}-{os.urandom(3).hex()}"
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


# What an unreadable session file is taken to mean: the worst that it could have recorded.
UNREADABLE_SESSION = {"external": 1, "flagged": 1, "flagged_reason": "session state was unreadable"}


def session(cfg, session_id: str) -> dict:
    """What the session has seen. Raises ValueError or OSError for a file that exists but cannot
    be read: that is not an empty session, and callers decide what the unknown costs them."""
    try:
        data = json.loads(_session_file(cfg, session_id).read_text())
    except FileNotFoundError:
        return {}
    if not isinstance(data, dict):
        raise ValueError("session state is not an object")
    return data


def session_update(cfg, session_id: str, *, paths: list = (), external: bool = False,
                   flagged: str = "") -> None:
    with _locked(_session_file(cfg, session_id), UNREADABLE_SESSION) as s:
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
        for p in cfg.sessions_dir.glob("*.json"):
            if p.stat().st_mtime < cutoff:
                p.unlink(missing_ok=True)
                Path(f"{p}.lock").unlink(missing_ok=True)
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
