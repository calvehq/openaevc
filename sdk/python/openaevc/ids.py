"""Typed identifiers: `<prefix>_<base32(uuidv7)>`."""
import os
import re
import time

from ._generated import ID_PREFIXES

ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"
_ID = re.compile(r"^([a-z]{2,3})_([a-z2-7]{26})$")


def base32(data: bytes) -> str:
    acc, bits, out = 0, 0, []
    for b in data:
        acc = (acc << 8) | b
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(ALPHABET[(acc >> bits) & 31])
        acc &= (1 << bits) - 1
    if bits:
        out.append(ALPHABET[(acc << (5 - bits)) & 31])
    return "".join(out)


def uuidv7(now_ms: int | None = None) -> bytes:
    ms = int(time.time() * 1000) if now_ms is None else now_ms
    b = bytearray(ms.to_bytes(6, "big") + os.urandom(10))
    b[6] = 0x70 | (b[6] & 0x0F)
    b[8] = 0x80 | (b[8] & 0x3F)
    return bytes(b)


def new_id(prefix: str) -> str:
    return f"{prefix}_{base32(uuidv7())}"


def parse_id(text: str, prefix: str | None = None) -> str:
    """Validates a typed ID (case-insensitive input); returns the canonical lowercase form."""
    # Case folding is ASCII-only, and the whole string must match (no trailing newline).
    if not text.isascii():
        raise ValueError(f"invalid identifier {text}")
    low = text.lower()
    m = _ID.fullmatch(low)
    if not m or m.group(1) not in ID_PREFIXES or (prefix and m.group(1) != prefix):
        raise ValueError(f"invalid identifier {text}")
    acc, bits, raw = 0, 0, bytearray()
    for ch in m.group(2):
        acc = (acc << 5) | ALPHABET.index(ch)
        bits += 5
        if bits >= 8:
            bits -= 8
            raw.append((acc >> bits) & 0xFF)
        acc &= (1 << bits) - 1
    if acc:
        raise ValueError(f"invalid identifier {text}: non-zero trailing bits")
    if raw[6] >> 4 != 7 or raw[8] >> 6 != 2:
        raise ValueError(f"invalid identifier {text}: not a UUIDv7")
    return low
