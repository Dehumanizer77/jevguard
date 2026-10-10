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
import re
import unicodedata

# Fields that say what kind of thing a block is, not text the model is given to read. A field is
# passed over only when its value is such a marker; the name of the field proves nothing, and a
# sentence under "type" or "mimeType" is read like any other text.
_PLUMBING = {
    "type": re.compile(r"text|image|audio|video|resource|resource_link|document|file|json|tool_use|tool_result|"
                       r"web_search_result|web_search_tool_result|search_result"),
    "mimeType": re.compile(r"(?:text|image|audio|video|application|font|model|multipart|message)/[A-Za-z0-9.+-]{1,60}"),
    "tool_use_id": re.compile(r"(?=[A-Za-z_]*\d)(?:srv)?toolu_[A-Za-z0-9]{8,48}"),
}
_NL_WORD = re.compile(r"[^\W\d_]{2,}")
_INVISIBLE = dict.fromkeys([0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E, *range(0x202A, 0x202F),
                            *range(0x2066, 0x206A), 0x00AD])


def words(text: str) -> int:
    """Words the model can read, counted after the same unhiding extraction does."""
    if any(0xE0000 <= ord(c) <= 0xE007F for c in text):
        text = "".join(chr(ord(c) - 0xE0000) if 0xE0000 <= ord(c) <= 0xE007F else c for c in text)
    return len(_NL_WORD.findall(unicodedata.normalize("NFKC", text.translate(_INVISIBLE))))


def _leaves(o, out: list, images: list, key: str = "") -> None:
    if isinstance(o, str):
        if not (key in _PLUMBING and _PLUMBING[key].fullmatch(o)):
            out.append(o)
    elif isinstance(o, dict):
        taken = None
        if o.get("type") == "image":  # MCP image block {type, data, mimeType} or {source: {data}}
            source = o.get("source") if isinstance(o.get("source"), dict) else {}
            taken = "data" if isinstance(o.get("data"), str) else "source" if isinstance(source.get("data"), str) else None
            if taken:
                images.append(o["data"] if taken == "data" else source["data"])
        for k, v in o.items():  # the picture is taken as a picture; whatever else the block holds is read
            if k == taken:
                v = {a: b for a, b in v.items() if a != "data"} if k == "source" else None
            _leaves(v, out, images, k)
    elif isinstance(o, list):
        for v in o:
            _leaves(v, out, images, key)


def _server_text(key: str, value) -> bool:
    """A WebFetch result's status phrase or address that is more than that: text to scan, and to
    leave out of a replacement."""
    if not isinstance(value, str) or not value:
        return False
    if key == "url":
        return not re.fullmatch(r"https?://\S{1,2000}", value)
    from http import HTTPStatus
    return value not in {s.phrase for s in HTTPStatus}


def server_texts(resp: dict) -> list[str]:
    return [resp[k] for k in ("codeText", "url") if _server_text(k, resp.get(k))]


def text_of(tool: str, resp) -> tuple[str, list[bytes]]:
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
        # The status phrase and the address are the server's too. They are left out only when
        # they are what they should be: a standard phrase, one address.
        texts = [str(resp.get("result") or ""), *server_texts(resp)]
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


# WebFetch does not follow a redirect to another host. It returns a notice of its own instead,
# captured here from Claude Code 2.1.295. Two things in it came from the server: the address in
# the Location header and the status line. The rest is the tool's words, the address that was
# asked for and the prompt the agent wrote.
_REDIRECT_FIRST = "REDIRECT DETECTED: The URL redirects to a location that was not fetched automatically."
_REDIRECT_SUPPLIED = re.compile(r"^Redirect URL \(from the server's Location header — server-supplied, not verified\): "
                                r"(\S+)\nStatus: ([^\n]*)$", re.M)
_ADDRESS = re.compile(r"https?://[!#-;=?-\[\]_a-z~]{1,2000}")  # printable ASCII without space " < > \ ^ ` { | }
_STATUS = re.compile(r"3\d\d(?: [ -~]{0,60})?")


def _redirect_notice(original: str, redirect: str, status: str, prompt: str) -> str:
    return (f"{_REDIRECT_FIRST}\n\n"
            f"Original URL: {original}\n"
            f"Redirect URL (from the server's Location header — server-supplied, not verified): {redirect}\n"
            f"Status: {status}\n\n"
            "To complete your request, I need to fetch content from the redirected URL. "
            "Please use WebFetch again with these parameters:\n"
            f'- url: "{redirect}"\n'
            f'- prompt: "{prompt}"')


def _line_edges(text: str) -> str:
    return "\n".join(line.strip() for line in text.strip().splitlines())


def redirect_supplied(tool_input: dict, text: str) -> str | None:
    """If a WebFetch result is that notice and nothing else: the two parts the server supplied,
    which are then all there is to scan. Else None, and the result is scanned whole.

    The notice is not recognised by its wording. It is written out again from the address and
    the prompt of this very call and the two parts found in the text, and has to come out equal
    to the text. A notice with a word added, another prompt or two different addresses is not
    equal. What the server can choose is an address without spaces and a short status line; both
    are still scored, the address also with its %-escapes decoded."""
    url, prompt = tool_input.get("url"), tool_input.get("prompt")
    if not text.startswith(_REDIRECT_FIRST) or not isinstance(url, str) or not isinstance(prompt, str):
        return None
    got = _line_edges(text)
    found = _REDIRECT_SUPPLIED.search(got)
    if not found or not _ADDRESS.fullmatch(found.group(1)) or not _STATUS.fullmatch(found.group(2)):
        return None
    redirect, status = found.groups()
    asked = {url, "https://" + url[len("http://"):] if url.startswith("http://") else url}  # the tool upgrades http
    if not any(got == _line_edges(_redirect_notice(original, redirect, status, prompt)) for original in asked):
        return None
    from urllib.parse import unquote
    decoded = unquote(redirect, errors="replace")
    return "\n".join([redirect, status] + ([decoded] if decoded != redirect else []))


def replaced(tool: str, resp, note: str):
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
        return {**resp, "result": note, **{k: "" for k in ("codeText", "url") if _server_text(k, resp.get(k))}}
    if isinstance(resp, dict) and tool == "WebSearch":
        return {**resp, "results": [note]}
    if isinstance(resp, list):
        return [{"type": "text", "text": note}]
    if isinstance(resp, dict) and isinstance(resp.get("content"), list):
        # Only the flags of the result are kept. Its other fields (structuredContent, ...) hold
        # the same text a second time and would hand it over beside the note.
        flags = {k: v for k, v in resp.items() if isinstance(v, (bool, int, float)) or v is None}
        return {**flags, "content": [{"type": "text", "text": note}]}
    return note
