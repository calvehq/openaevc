"""SHA-256 digests and Ed25519 signatures with OpenAEVC domain separation."""
import base64
import hashlib
import os
import re

from . import ed25519 as _pure
from .canonical import encode

_FAST = False
if os.environ.get("OPENAEVC_CRYPTO") == "cryptography":  # opt-in acceleration
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
        from cryptography.hazmat.primitives import serialization
        from cryptography.exceptions import InvalidSignature

        _FAST = True
    except ImportError:
        _FAST = False
    except BaseException as e:  # broken native installs raise pyo3 PanicException
        if type(e).__name__ != "PanicException":
            raise
        _FAST = False

DOMAINS = ("request", "grant", "object")


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest_of(value) -> str:
    return sha256(encode(value))


def signing_digest(envelope: dict) -> str:
    """SHA-256 of an object envelope's canonical encoding without `signatures`: object
    signatures cover its 32 raw bytes (`object` domain); references use `digest_of(envelope)`."""
    return digest_of({k: v for k, v in envelope.items() if k != "signatures"})


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def from_b64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _message(domain: str, msg: bytes) -> bytes:
    if domain not in DOMAINS:
        raise ValueError(f"unknown signature domain {domain}")
    return f"OPENAEVC/1 {domain}\n".encode() + msg


class SigningKey:
    """An in-memory Ed25519 key created from its 32-byte seed."""

    def __init__(self, seed: bytes):
        if len(seed) != 32:
            raise ValueError("Ed25519 seed must be 32 bytes")
        self.seed = seed
        if _FAST:
            self._key = Ed25519PrivateKey.from_private_bytes(seed)
            raw = self._key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        else:
            raw = _pure.public_key(seed)
        self.public_key = "ed25519:" + b64url(raw)

    @classmethod
    def generate(cls) -> "SigningKey":
        return cls(os.urandom(32))

    @classmethod
    def from_hex(cls, h: str) -> "SigningKey":
        return cls(bytes.fromhex(h.strip()))

    def sign(self, domain: str, msg: bytes) -> str:
        m = _message(domain, msg)
        sig = self._key.sign(m) if _FAST else _pure.sign(self.seed, m)
        return b64url(sig)


def _strict_b64(s: str, n: int):
    """Canonical unpadded base64url of exactly `n` bytes, else None."""
    if not isinstance(s, str) or not _B64.fullmatch(s):
        return None
    try:
        b = from_b64url(s)
    except ValueError:
        return None
    return b if len(b) == n and b64url(b) == s else None


_B64 = re.compile(r"[A-Za-z0-9_-]*")
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
# Encodings (sign bit cleared) of points of small order, canonical or not (as in libsodium).
_SMALL_ORDER = {
    bytes(32),
    bytes([1]) + bytes(31),
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    bytes.fromhex("ec" + "ff" * 30 + "7f"),
    bytes.fromhex("ed" + "ff" * 30 + "7f"),
    bytes.fromhex("ee" + "ff" * 30 + "7f"),
}


def _weak_point(enc: bytes) -> bool:
    cleared = enc[:31] + bytes([enc[31] & 0x7F])
    return cleared in _SMALL_ORDER or int.from_bytes(cleared, "little") >= _P


def verify(public_key: str, domain: str, msg: bytes, signature: str) -> bool:
    """Strict Ed25519 (AEVC-ID-0006): canonical encodings, no small-order key or R, S < L."""
    if not isinstance(public_key, str) or not public_key.startswith("ed25519:"):
        return False
    raw = _strict_b64(public_key[len("ed25519:"):], 32)
    sig = _strict_b64(signature, 64)
    if raw is None or sig is None:
        return False
    if _weak_point(raw) or _weak_point(sig[:32]) or int.from_bytes(sig[32:], "little") >= _L:
        return False
    m = _message(domain, msg)
    if _FAST:
        try:
            Ed25519PublicKey.from_public_bytes(raw).verify(sig, m)
            return True
        except (InvalidSignature, ValueError):
            return False
    return _pure.verify(raw, m, sig)
