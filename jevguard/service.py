"""The service of a system installation (system.py). It runs as the user jevguard, holds the API
key, the seal key and the guard's state, and does for the hooks what needs them.

One request per line on a Unix socket, as JSON: {"call": NAME, "args": [...], "kwargs": {...}}.
One answer per line: {"result": ...} or {"error": TEXT}. Bytes go as {"\\u0000bytes": BASE64}.

What it answers: the reads and writes of the guard's state that a hook makes (store.REMOTE), a
scan, and a seal. Nothing that changes the owner's decisions: a release, a discard and the
settings are the owner's commands, run as root, and are not answered here. It answers root and
the owners named in system.json, by the credentials the kernel gives for the socket.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import socketserver
import struct
import sys

from . import system

MAX_LINE = 64 * 1024 * 1024  # a tool result with its images, as JSON
_BYTES = "\0bytes"


class ServiceError(OSError):
    """The service could not be reached, or could not do what it was asked. An OSError, as the
    files it stands for would raise: callers treat it as they treat a file they cannot read."""


def _pack(value):
    if isinstance(value, (bytes, bytearray)):
        return {_BYTES: base64.b64encode(bytes(value)).decode()}
    if isinstance(value, dict):
        return {str(k): _pack(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_pack(v) for v in value]
    return value


def _unpack(value):
    if isinstance(value, dict):
        if set(value) == {_BYTES} and isinstance(value[_BYTES], str):
            return base64.b64decode(value[_BYTES])
        return {k: _unpack(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_unpack(v) for v in value]
    return value


class Client:
    """A hook's connection to the service: one for the life of the process, opened on first use."""

    def __init__(self, path: str | None = None, timeout: float = 60.0):
        self.path, self.timeout = path or system.SOCKET, timeout
        self._sock = self._file = None

    def close(self) -> None:
        for f in (self._file, self._sock):
            try:
                if f is not None:
                    f.close()
            except OSError:
                pass
        self._sock = self._file = None

    def call(self, name: str, *args, **kwargs):
        request = (json.dumps({"call": name, "args": _pack(list(args)), "kwargs": _pack(kwargs)},
                              ensure_ascii=False, default=str) + "\n").encode("utf-8", "surrogatepass")
        if len(request) > MAX_LINE:
            raise ServiceError(f"a request of {len(request)} bytes is more than the service takes")
        reused = self._sock is not None
        for attempt in (0, 1):
            try:
                if self._sock is None:
                    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    s.settimeout(self.timeout)
                    s.connect(self.path)
                    self._sock, self._file = s, s.makefile("rb")
                self._sock.sendall(request)
                line = self._file.readline(MAX_LINE + 1)
                if not line:
                    raise ConnectionError("the service closed the connection")
                break
            except OSError as exc:
                self.close()
                if attempt or not reused:  # a connection kept from before may have been closed by a restart
                    raise ServiceError(f"jevguard service at {self.path}: {exc}") from None
        try:
            answer = json.loads(line)
        except ValueError:
            self.close()
            raise ServiceError("the service's answer is not JSON") from None
        if not isinstance(answer, dict) or "error" in answer:
            raise ServiceError(str(answer.get("error") if isinstance(answer, dict) else answer))
        return _unpack(answer.get("result"))


class Scanner:
    """scanner.Scanner for a hook of a system installation: the service scores, with its key."""

    def __init__(self, cfg):
        self.client, self.policy_id = cfg.service, ""

    def scan(self, text: str, images: list[bytes]):
        from .scanner import ScanFailed
        try:
            out = self.client.call("scan", text, list(images))
        except ServiceError as exc:
            return {}, ScanFailed(str(exc), outage=True)
        self.policy_id = out.get("policy") or ""
        err = out.get("error")
        return out.get("verdict") or {}, ScanFailed(err["message"], outage=bool(err.get("outage"))) if err else None


# ---- the service ---------------------------------------------------------------------------------

def _scan(cfg, text: str, images: list) -> dict:
    from . import config, scanner
    key = config.read_key(cfg)
    if not key:
        return {"verdict": {}, "error": {"message": "no API key", "outage": False}}
    sc = scanner.Scanner(cfg, key)
    verdict, err = sc.scan(text, [i for i in images if isinstance(i, bytes)])
    return {"verdict": verdict, "policy": sc.policy_id,
            "error": None if err is None else {"message": str(err), "outage": err.outage}}


def _seal(cfg, text: str) -> str:
    from . import firstparty
    if firstparty._secret is None:
        firstparty.use(cfg)
    return firstparty._mac(str(text))


def _scanner_available(cfg) -> str:
    from . import config, store
    return "no API key" if not config.read_key(cfg) else store.scanner_available(cfg)


def dispatch(cfg, name: str, args: list, kwargs: dict):
    """One request, done with the service's own files."""
    from . import store
    if name == "scan":
        return _scan(cfg, *args, **kwargs)
    if name == "seal":
        return _seal(cfg, *args, **kwargs)
    if name == "scanner_available":
        return _scanner_available(cfg)
    if name in store.REMOTE:
        return getattr(store, name)(cfg, *args, **kwargs)
    raise ValueError(f"the service does not answer {name!r}")


def _peer_uid(sock) -> int:
    creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", creds)[1]


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        uid = _peer_uid(self.request)
        if uid not in self.server.allowed():
            self._answer({"error": f"user {uid} is not an owner of this installation"})
            return
        while line := self.rfile.readline(MAX_LINE + 1):
            try:
                if len(line) > MAX_LINE:
                    raise ValueError("request too large")
                req = json.loads(line)
                if not isinstance(req, dict) or not isinstance(req.get("call"), str):
                    raise ValueError("not a request")
                args, kwargs = _unpack(req.get("args") or []), _unpack(req.get("kwargs") or {})
                if not isinstance(args, list) or not isinstance(kwargs, dict):
                    raise ValueError("not a request")
                answer = {"result": _pack(dispatch(self.server.load(), req["call"], args, kwargs))}
            except Exception as exc:  # noqa: BLE001 - every failure is an answer, never a dropped hook
                answer = {"error": f"{type(exc).__name__}: {exc}"[:500]}
            self._answer(answer)

    def _answer(self, answer: dict) -> None:
        self.wfile.write((json.dumps(answer, ensure_ascii=False, default=str) + "\n").encode("utf-8", "surrogatepass"))


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """load: the settings for one request (read afresh, so that the owner's `mode` takes effect
    at once); allowed: the uids it answers."""
    daemon_threads = True

    def __init__(self, sock: socket.socket, load, allowed):
        super().__init__(system.SOCKET, _Handler, bind_and_activate=False)
        self.socket.close()
        self.socket, self.load, self.allowed = sock, load, allowed


def _owners() -> set[int]:
    found = system.settings() or {}
    return {0, os.getuid(), *[u for u in found.get("users", []) if isinstance(u, int)]}


def main() -> None:
    """The service, as systemd starts it: its socket is handed over as file descriptor 3."""
    from . import config
    os.umask(0o077)
    if os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1":
        sys.exit("jevguard-service is started by systemd (jevguard.socket)")
    sock = socket.socket(fileno=3)
    if system.settings() is None:
        sys.exit(f"{system.SYSTEM_FILE} does not name this code ({system.CODE_ROOT}); run setup-system")
    try:
        from . import firstparty
        firstparty.use(config.load())  # the seal key, made now if there is none yet
    except Exception as exc:  # noqa: BLE001 - scans go on without it
        print(f"no seal key: {exc}", file=sys.stderr)
    Server(sock, config.load, _owners).serve_forever()
