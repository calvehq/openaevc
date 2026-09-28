"""SHA-256 digests and Ed25519 signatures with OpenAEVC domain separation."""
import base64
import hashlib
import os

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


def verify(public_key: str, domain: str, msg: bytes, signature: str) -> bool:
    raw = from_b64url(public_key.removeprefix("ed25519:"))
    sig = from_b64url(signature)
    m = _message(domain, msg)
    if _FAST:
        try:
            Ed25519PublicKey.from_public_bytes(raw).verify(sig, m)
            return True
        except (InvalidSignature, ValueError):
            return False
    return _pure.verify(raw, m, sig)
