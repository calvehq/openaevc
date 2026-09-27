"""Write OpenAEVC extensions in Python (spec/extensions.md, subprocess mode).

Subclass `Extension`, implement `manifest()` and `handle(op, host)`, and call `serve(ext)`.
Frames are 4-byte big-endian lengths followed by canonical CBOR.
"""
import hashlib
import os
import struct
import sys

from ._generated import CONTRACT_VERSION, PROTOCOL_VERSION
from .canonical import decode, encode

MAX_FRAME = 16 * 1024 * 1024


class ExtensionError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


def _read(stream):
    head = stream.read(4)
    if not head:
        return None
    if len(head) < 4:
        raise EOFError("truncated frame")
    (n,) = struct.unpack(">I", head)
    if n > MAX_FRAME:
        raise ValueError("frame too large")
    body = stream.read(n)
    if len(body) < n:
        raise EOFError("truncated frame")
    return decode(body)


def _write(stream, msg: dict) -> None:
    body = encode(msg)
    stream.write(struct.pack(">I", len(body)) + body)
    stream.flush()


def artifact_digest(path: str) -> str:
    """SHA-256 of the extension artifact (the executable file being run)."""
    with open(path, "rb") as f:
        return "sha256:" + hashlib.sha256(f.read()).hexdigest()


class Host:
    """Host calls available during one invocation."""

    def __init__(self, invocation: int, granted, rin, rout):
        self.invocation, self.granted = invocation, list(granted)
        self._rin, self._rout, self._next = rin, rout, 0

    def call(self, request: dict):
        self._next += 1
        _write(self._rout, {"type": "host_call", "invocation": self.invocation, "call": self._next, "request": request})
        msg = _read(self._rin)
        if not msg or msg.get("type") != "host_result" or msg.get("call") != self._next:
            raise ExtensionError("protocol", "unexpected host message")
        if "error" in msg:
            raise ExtensionError(msg["error"]["code"], msg["error"]["message"])
        return msg.get("ok")


class Extension:
    def manifest(self) -> dict:
        raise NotImplementedError

    def handle(self, op: dict, host: Host):
        raise NotImplementedError


def version_range() -> dict:
    return {"min": PROTOCOL_VERSION, "max": PROTOCOL_VERSION}


def contract_range() -> dict:
    return {"min": CONTRACT_VERSION, "max": CONTRACT_VERSION}


def serve(ext: Extension) -> int:
    rin, rout = sys.stdin.buffer, sys.stdout.buffer
    hello = _read(rin)
    if not hello or hello.get("type") != "hello":
        return 1
    m = ext.manifest()
    _write(rout, {"type": "hello", "manifest": m, "protocol": m["protocol"], "contract": m["contract"]})
    while True:
        msg = _read(rin)
        if msg is None or msg.get("type") == "shutdown":
            return 0
        if msg.get("type") != "invoke":
            continue
        host = Host(msg["id"], msg.get("granted", []), rin, rout)
        try:
            out = ext.handle(msg["operation"], host)
            _write(rout, {"type": "result", "id": msg["id"], "output": out})
        except ExtensionError as e:
            _write(rout, {"type": "error", "id": msg["id"], "error": {"code": e.code, "message": e.message}})


def self_path() -> str:
    return os.path.abspath(sys.argv[0])
