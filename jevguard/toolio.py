"""What the model would read from a Claude Code tool result, and a replacement of the same shape.

Shapes were captured from PostToolUse payloads of Claude Code 2.1.295:
  Bash       {stdout, stderr, interrupted, isImage, noOutputExpected}
  Read       {type: "text", file: {filePath, content, numLines, startLine, totalLines}}
             {type: "image", file: {base64, type, originalSize, dimensions}}
  Grep       {mode, numFiles, filenames, content, numLines, totalLines}
  WebFetch   {bytes, code, codeText, result, durationMs, url}
  WebSearch  {query, results: [{tool_use_id, content: [{title, url}]}, "summary text", ...]}
  mcp__*     [{type: "text", text}, ...]
A built-in tool's replacement must keep its shape, or Claude Code ignores it and shows the original.
"""

from __future__ import annotations

import base64
import binascii
from typing import Any

_PLUMBING_KEYS = {"type", "tool_use_id", "mimeType"}


def _leaves(o: Any, out: list, images: list) -> None:
    if isinstance(o, str):
        out.append(o)
    elif isinstance(o, dict):
        if o.get("type") == "image":  # MCP image block {type, data, mimeType} or {source: {data}}
            data = o.get("data") or (o.get("source") or {}).get("data")
            if isinstance(data, str):
                images.append(data)
            return
        for k, v in o.items():
            if k not in _PLUMBING_KEYS:
                _leaves(v, out, images)
    elif isinstance(o, list):
        for v in o:
            _leaves(v, out, images)


def text_of(tool: str, resp: Any) -> tuple[str, list[bytes]]:
    """(model-visible text, images as bytes) of a tool result."""
    texts: list = []
    b64: list = []
    if isinstance(resp, dict) and tool == "Bash":
        texts = [str(resp.get(k) or "") for k in ("stdout", "stderr")]
    elif isinstance(resp, dict) and tool == "Read":
        f = resp.get("file") or {}
        if resp.get("type") == "image" and isinstance(f.get("base64"), str):
            b64.append(f["base64"])
        else:
            texts = [str(f.get("content") or "")]
    elif isinstance(resp, dict) and tool == "Grep":
        texts = [str(resp.get("content") or ""), *map(str, resp.get("filenames") or [])]
    elif isinstance(resp, dict) and tool == "WebFetch":
        texts = [str(resp.get("result") or "")]
    elif isinstance(resp, dict) and tool == "WebSearch":
        _leaves(resp.get("results"), texts, b64)
    else:
        _leaves(resp, texts, b64)
    images = []
    for s in b64:
        try:
            images.append(base64.b64decode(s, validate=False))
        except (binascii.Error, ValueError):
            images.append(b"")
    return "\n".join(t for t in texts if t), images


def replaced(tool: str, resp: Any, note: str) -> Any:
    """The tool result with its content replaced by note, in the shape the tool returns."""
    if isinstance(resp, dict) and tool == "Bash":
        return {**resp, "stdout": note, "stderr": "", "isImage": False}
    if isinstance(resp, dict) and tool == "Read":
        f = resp.get("file") or {}
        return {"type": "text", "file": {"filePath": f.get("filePath", ""), "content": note,
                                         "numLines": 1, "startLine": 1, "totalLines": 1}}
    if isinstance(resp, dict) and tool == "Grep":
        return {**resp, "mode": "content", "numFiles": 0, "filenames": [], "content": note,
                "numLines": 1, "totalLines": 1}
    if isinstance(resp, dict) and tool == "WebFetch":
        return {**resp, "result": note}
    if isinstance(resp, dict) and tool == "WebSearch":
        return {**resp, "results": [note]}
    if isinstance(resp, list):
        return [{"type": "text", "text": note}]
    if isinstance(resp, dict) and isinstance(resp.get("content"), list):
        return {**resp, "content": [{"type": "text", "text": note}]}
    return note
