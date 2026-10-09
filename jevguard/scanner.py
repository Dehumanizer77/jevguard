"""Extract, score with Jev, decide. The verdict is computed in code from the model's
probabilities; the model is never asked for a verdict."""

from __future__ import annotations

import hashlib
import json
import re
import time
import unicodedata
from pathlib import Path

from .core import jev_detector
from .core.extract import extract
from .core.jev_detector import JevDetector, JevError
from .core.policy import Policy

jev_detector.RETRY_CODES.add(529)  # TypeSafe's "overloaded", not in the upstream (Venice) list

_POLICY_FILE = Path(__file__).parent / "core" / "policy-jev.json"
_RANK = {"safe": 0, "suspicious": 1, "injection": 2}
# Flags that mean part of the result never reached the scorer.
INCOMPLETE = {"ocr_unavailable", "ocr_failed", "image_unreadable", "image_unscanned", "scan_truncated",
              "scan_incomplete"}
MAX_IMAGES = 8
MAX_IMAGE_BYTES = 15 * 1024 * 1024
_NL_WORD = re.compile(r"[^\W\d_]{2,}")
_INVISIBLE = dict.fromkeys([0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E, *range(0x202A, 0x202F),
                            *range(0x2066, 0x206A), 0x00AD])


class ScanFailed(RuntimeError):
    """Scanning did not finish. outage: the scanner is failing, not just this input.
    partial: the verdict over what was scored before the failure, if anything was."""

    def __init__(self, msg: str, *, outage: bool = True, partial: dict | None = None):
        super().__init__(msg)
        self.outage, self.partial = outage, partial


def words(text: str) -> int:
    """Words the model can read, counted after the same unhiding extraction does."""
    if any(0xE0000 <= ord(c) <= 0xE007F for c in text):
        text = "".join(chr(ord(c) - 0xE0000) if 0xE0000 <= ord(c) <= 0xE007F else c for c in text)
    return len(_NL_WORD.findall(unicodedata.normalize("NFKC", text.translate(_INVISIBLE))))


def load_policy() -> tuple[Policy, str]:
    raw = _POLICY_FILE.read_text()
    return Policy(**json.loads(raw)), hashlib.sha256(raw.encode()).hexdigest()[:12]


def merge(a: dict | None, b: dict | None) -> dict | None:
    """Evidence of two parts of one result: the worse verdict, the higher score, every reason,
    flag and signal."""
    if a is None or b is None:
        return a if b is None else b
    top = b if _RANK.get(b.get("verdict"), 0) > _RANK.get(a.get("verdict"), 0) else a
    scores = [s for s in (a.get("score"), b.get("score")) if isinstance(s, (int, float))]
    out = dict(top, score=max(scores) if scores else None,
               reasons=list(dict.fromkeys([*(a.get("reasons") or []), *(b.get("reasons") or [])])),
               flags=list(dict.fromkeys([*(a.get("flags") or []), *(b.get("flags") or [])])),
               tokens=(a.get("tokens") or 0) + (b.get("tokens") or 0),
               n_chunks=(a.get("n_chunks") or 0) + (b.get("n_chunks") or 0))
    sig = dict(a.get("signals") or {})
    for k, x in (b.get("signals") or {}).items():
        sig[k] = max(sig.get(k, x), x)
    out["signals"] = sig
    return out


def unscanned(flag: str, reason: str) -> dict:
    """Verdict for a part the scanner could not look at: never safe."""
    return {"verdict": "suspicious", "score": None, "reasons": [f"not fully scanned: {reason}"], "flags": [flag]}


class Scanner:
    def __init__(self, cfg, key: str):
        self.policy, self.policy_id = load_policy()
        self.jev = JevDetector(key, model=cfg.model, questions=self.policy.questions, timeout=cfg.timeout,
                               attempts=2, url=cfg.url, max_wait=cfg.deadline)
        self.deadline_s = cfg.deadline
        self.min_words = cfg.min_words

    def _decide(self, ex, deadline: float) -> dict:
        err = None
        try:
            sig = self.jev.score_many([ex.text], deadline=deadline)[0] if ex.text.strip() else {}
        except JevError as e:
            if e.partial is None:
                raise ScanFailed(str(e), outage=e.outage) from e
            sig, err = e.partial, e
        flags = list(ex.flags) + (["scan_incomplete"] if err else [])
        v = self.policy.decide(sig, flags)
        v.update(flags=flags, signals={k: round(x, 4) for k, x in sig.items() if k in self.policy.questions},
                 n_chunks=sig.get("n_chunks") or 0, tokens=sig.get("tokens") or 0)
        if err is not None and v["verdict"] != "injection":  # nothing conclusive before the failure
            raise ScanFailed(str(err), outage=err.outage, partial=v)
        return v

    def scan(self, text: str, images: list[bytes]) -> tuple[dict, ScanFailed | None]:
        """(verdict, error). An error stops the scan but keeps everything already found."""
        verdict = None
        deadline = time.monotonic() + self.deadline_s
        try:
            if words(text) >= self.min_words:
                verdict = self._decide(extract(text), deadline)
            for img in images[:MAX_IMAGES]:
                if not img or len(img) > MAX_IMAGE_BYTES:
                    verdict = merge(verdict, unscanned("image_unreadable", "image could not be decoded"))
                    continue
                try:
                    ex = extract(img, kind="image")
                except Exception:
                    verdict = merge(verdict, unscanned("image_unreadable", "image could not be decoded"))
                    continue
                verdict = merge(verdict, self._decide(ex, deadline))
        except ScanFailed as e:
            return merge(verdict, e.partial) or {}, e
        if len(images) > MAX_IMAGES:
            verdict = merge(verdict, unscanned("image_unscanned", f"{len(images) - MAX_IMAGES} images over the "
                                                                  f"limit of {MAX_IMAGES}"))
        return verdict or {"verdict": "safe", "score": 0, "reasons": [], "flags": []}, None
