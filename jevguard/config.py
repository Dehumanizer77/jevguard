"""Settings and file locations. Defaults live here; ~/.config/jevguard/config.json overrides them."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

DEFAULTS = {
    # "log": scan and record, change nothing. "block": withhold results that score as an injection.
    "mode": "log",
    # Risky actions (send data out, push, write to startup files) in a session that saw outside
    # content: "off", "log" (record what would have been asked), "ask-flagged" (ask once a result
    # scored as an injection or passed unscanned), "ask-external" (ask after any outside content).
    "gate": "log",
    "url": "https://api.typesafe.ai/v1/systemone",
    # Pinned: the thresholds in core/policy-jev.json were fitted on Jev 1.13. A moved alias would
    # change the score scale under them without notice.
    "model": "jev-1.13.0",
    "key_file": "~/.config/jevguard/typesafe.key",
    # Everything scanned is sent to the scoring API. Local files and local command output stay on
    # this machine unless this is switched on (they then block at local_block, not at the policy level).
    "scan_local": False,
    "local_block": 0.6,
    # Fetches from localhost and private addresses count as local content.
    "scan_private_hosts": False,
    # Files under these directories are outside content, whatever tool reads them.
    "external_paths": ["~/Downloads"],
    # Directories created by `git clone` count as outside content for the rest of the session.
    "track_clones": False,
    # Tool names (regular expressions, full match) never scanned / scanned but never blocked.
    "skip_tools": ["mcp__claude_ai_Gmail__.*", "mcp__claude_ai_Google_Drive__.*",
                   "mcp__claude_ai_Google_Calendar__.*", "mcp__claude_ai_Claude_Docs__.*"],
    "warn_tools": [],
    "trusted_commands": [],
    # Addresses whose content is scanned and logged but never withheld, as URL prefixes
    # ("https://developers.openai.com/codex/"). For sources that keep scoring as an injection
    # without being one: documentation about hooks, articles about prompt injection. Whatever such
    # an address returns later, or redirects to, passes unread by anyone; keep the prefixes narrow.
    "trusted_sources": [],
    # When scanning fails: "open" passes the result, "closed" withholds outside content.
    "on_error": "open",
    # Ask before any call that would change the guard: its settings, state, release list, code,
    # or the Claude Code settings files that run it. Applies in every session, whatever gate says.
    "protect_guard": True,
    "timeout": 5.0,           # one request
    "deadline": 20.0,         # one tool result, all chunks
    "breaker_seconds": 60.0,  # pause after the API failed
    "daily_token_budget": 5_000_000,  # about $0.21 a day at $0.042 per million tokens
    "min_words": 3,
    # A file counts as written by a command only if it is there afterwards. Names a command did
    # not really create (an option value read as a file name) would otherwise be tracked too, and
    # every later output that happens to contain such a word would be sent for scoring.
    "track_missing_files": False,
}


def root() -> tuple[Path, Path]:
    """(config dir, state dir). JEVGUARD_HOME moves both under one directory (tests)."""
    home = os.environ.get("JEVGUARD_HOME")
    if home:
        return Path(home) / "config", Path(home) / "state"
    return Path.home() / ".config" / "jevguard", Path.home() / ".local" / "state" / "jevguard"


def load() -> SimpleNamespace:
    cfg_dir, state_dir = root()
    values = dict(DEFAULTS)
    path = cfg_dir / "config.json"
    if path.exists():
        user = json.loads(path.read_text())
        unknown = sorted(set(user) - set(DEFAULTS))
        if unknown:
            raise ValueError(f"{path}: unknown setting(s) {', '.join(unknown)}")
        values.update(user)
    if values["mode"] not in ("log", "block"):
        raise ValueError(f"{path}: mode must be log or block")
    if values["gate"] not in ("off", "log", "ask-flagged", "ask-external"):
        raise ValueError(f"{path}: gate must be off, log, ask-flagged or ask-external")
    if values["on_error"] not in ("open", "closed"):
        raise ValueError(f"{path}: on_error must be open or closed")
    for source in values["trusted_sources"]:
        if not isinstance(source, str) or not source.lower().startswith(("https://", "http://")):
            raise ValueError(f"{path}: trusted_sources takes URL prefixes starting with https:// or http://")
    cfg = SimpleNamespace(**values)
    cfg.config_dir, cfg.state_dir, cfg.config_file = cfg_dir, state_dir, path
    if os.environ.get("JEVGUARD_HOME") and values["key_file"] == DEFAULTS["key_file"]:
        cfg.key_file = str(cfg_dir / "typesafe.key")
    cfg.key_file = os.path.expanduser(cfg.key_file)
    cfg.quarantine_dir = state_dir / "quarantine"
    cfg.sessions_dir = state_dir / "sessions"
    cfg.scan_log = state_dir / "scans.jsonl"
    cfg.released_file = state_dir / "released.txt"
    cfg.usage_file = state_dir / "usage.json"
    # Released originals are handed to the agent as files. They live outside the state directory
    # on purpose: that one is closed to Claude Code's file tools, this one has to be readable.
    home = os.environ.get("JEVGUARD_HOME")
    cfg.released_dir = Path(home) / "released" if home else state_dir.with_name(state_dir.name + "-released")
    return cfg


def read_key(cfg) -> str:
    """The API key, or an empty string when the file is missing or is not text."""
    try:
        return Path(cfg.key_file).read_text().strip()
    except (OSError, ValueError):
        return ""
