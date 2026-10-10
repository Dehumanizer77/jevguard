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
                       r"web_search_result|web_search_tool_result|search_result|"
                       r"(?:text|image|audio|video|application)/[A-Za-z0-9.+-]{1,60}"),  # Read: {file: {type: "image/png"}}
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
    elif isinstance(resp, dict) and tool == "Read" and isinstance(resp.get("file"), dict):
        f = resp["file"]
        if resp.get("type") == "image" and isinstance(f.get("base64"), str):
            b64.append(f["base64"])
            _leaves({k: v for k, v in f.items() if k != "base64"}, texts, b64)  # whatever else stands beside the picture
        elif resp.get("type") in (None, "text") and isinstance(f.get("content"), str):
            texts = [f["content"]]  # the one shape recorded above; the path beside it is the call's own
        else:
            # Another kind of file (a notebook, a PDF) or a shape not seen before. It used to be
            # read as a text file with no content, that is, not at all. Everything in it is read.
            _leaves(resp, texts, b64)
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


# A result too large to hand over is put in a file of the session,
#   <the transcript's path without .jsonl>/tool-results/<name>,
# and the model is told to read that instead (seen in 2.1.295):
#   Bash         stdout is cut to its first 30,000 characters; persistedOutputPath and
#                persistedOutputSize are added. The model gets a 2 KB preview and the path.
#   an MCP tool  from about 100 KB: the hook gets none of the content. The result is the message
#                below, a string, and that is all the model gets too.
# Either way the content the hook did not see is in that file, and the file is this call's output
# (saved_paths). The MCP message is the tool's own words around three things: sizes, the path, and
# a line that says what form the content has, which is made from the content.
_SAVED = re.compile(r"Error: result \(([\d,]{1,20}) characters across (\d{1,12}) lines\) exceeds maximum allowed tokens\. "
                    r"Output has been saved to (\S+)\.\nFormat: ([^\n]*)\n")
_SAVED_CHUNK = re.compile(r"in chunks of ~(\d{1,9}) lines")
_STORED = re.compile(r"/[^\s\"'<>|]*/tool-results/[^\s\"'<>|/]+")


def _saved_notice(chars: str, lines: str, path: str, form: str, chunk: str) -> str:
    return (f"Error: result ({chars} characters across {lines} lines) exceeds maximum allowed tokens. "
            f"Output has been saved to {path}.\n"
            f"Format: {form}\n"
            "- For targeted searches (find a line, locate a string): use grep on the file directly.\n"
            f"- For analysis or summarization that requires reading the full content: read {path} in chunks of "
            f"~{chunk} lines using offset/limit until you have read 100% of it.\n"
            "- If the Agent tool is available, do this inside a subagent so the full output stays out of your main "
            "context. Give it the instruction above verbatim, and be explicit about what it must return — e.g. "
            f'"Read {path} in chunks of ~{chunk} lines using offset/limit until you have read all {lines} lines, then '
            'summarize and quote any key findings verbatim." A vague "summarize this" may lose detail.\n')


def result_store(transcript_path) -> str:
    """The directory this session's oversized results are saved in, or "" when it cannot be told."""
    path = str(transcript_path or "")
    return path[:-len(".jsonl")] + "/tool-results" if path.endswith(".jsonl") and len(path) > len(".jsonl") else ""


def saved_notice_format(text: str, store: str) -> str | None:
    """If a result is that message and nothing else, about a file in this session's own store:
    its format line, the one part of it made from the content, which is then all there is to
    scan here (the content itself is scanned when the file is read). Else None, and the result
    is scanned whole. As with the redirect notice, the message is not known by its wording: it is
    written out again from the parts found in it and has to come out equal."""
    found, chunk = _SAVED.match(text), _SAVED_CHUNK.search(text)
    if not store or not found or not chunk:
        return None
    chars, lines, path, form = found.groups()
    name = path[len(store) + 1:] if path.startswith(store + "/") else ""
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,200}", name) or name.startswith("."):
        return None
    return form if text.strip() == _saved_notice(chars, lines, path, form, chunk.group(1)).strip() else None


def saved_paths(resp, store: str) -> list[str]:
    """The files a result says its content was saved to. With the store known, only files in it;
    without, anything that reads like one. Tracking a file too many costs a scan."""
    texts: list = []
    _leaves(resp, texts, [])
    named = [m for t in texts for m in _STORED.findall(t)]
    if isinstance(resp, dict) and isinstance(resp.get("persistedOutputPath"), str):
        named.insert(0, resp["persistedOutputPath"])
    return list(dict.fromkeys(p.rstrip(".,;:)") for p in named if not store or p.startswith(store + "/")))


def replaced(tool: str, resp, note: str):
    """The tool result with its content replaced by note, in the shape the tool returns."""
    if isinstance(resp, dict) and tool == "Bash":
        # not the fields that say where the whole output was saved: that file is the original
        kept = {k: v for k, v in resp.items() if k not in ("persistedOutputPath", "persistedOutputSize")}
        return {**kept, "stdout": note, "stderr": "", "isImage": False}
    if isinstance(resp, dict) and tool == "Read":
        f = resp.get("file") if isinstance(resp.get("file"), dict) else {}  # whatever came: this must not fail
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
