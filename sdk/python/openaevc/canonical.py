"""Deterministic CBOR of the JSON data model (spec/canonical-encoding.md).

Integers within +/-(2**53-1), text keys sorted by their encoded bytes, definite lengths, no
floats/None/tags/byte strings. Decoding is strict: anything non-canonical is rejected.
"""

MAX_SAFE = (1 << 53) - 1
MAX_DEPTH = 128


class CanonicalError(ValueError):
    pass


def _head(out: bytearray, major: int, n: int) -> None:
    m = major << 5
    if n < 24:
        out.append(m | n)
    elif n <= 0xFF:
        out += bytes([m | 24, n])
    elif n <= 0xFFFF:
        out.append(m | 25)
        out += n.to_bytes(2, "big")
    elif n <= 0xFFFFFFFF:
        out.append(m | 26)
        out += n.to_bytes(4, "big")
    else:
        out.append(m | 27)
        out += n.to_bytes(8, "big")


def _encode(v, out: bytearray) -> None:
    if v is None:
        raise CanonicalError("null is not permitted in canonical objects")
    if isinstance(v, bool):
        out.append(0xF5 if v else 0xF4)
    elif isinstance(v, int):
        if abs(v) > MAX_SAFE:
            raise CanonicalError("integer outside +/-(2^53-1)")
        if v >= 0:
            _head(out, 0, v)
        else:
            _head(out, 1, -1 - v)
    elif isinstance(v, float):
        raise CanonicalError("floating-point values are not permitted")
    elif isinstance(v, str):
        b = v.encode("utf-8")
        _head(out, 3, len(b))
        out += b
    elif isinstance(v, (list, tuple)):
        _head(out, 4, len(v))
        for item in v:
            _encode(item, out)
    elif isinstance(v, dict):
        entries = []
        for k, val in v.items():
            if not isinstance(k, str):
                raise CanonicalError("map keys must be text")
            kb = bytearray()
            _encode(k, kb)
            entries.append((bytes(kb), val))
        entries.sort(key=lambda e: e[0])
        _head(out, 5, len(entries))
        for kb, val in entries:
            out += kb
            _encode(val, out)
    else:
        raise CanonicalError(f"unsupported type {type(v).__name__}")


def encode(v) -> bytes:
    out = bytearray()
    _encode(v, out)
    return bytes(out)


def decode(data: bytes):
    pos = 0

    def take(n: int) -> bytes:
        nonlocal pos
        if pos + n > len(data):
            raise CanonicalError("truncated")
        s = data[pos:pos + n]
        pos += n
        return s

    def arg(info: int) -> int:
        if info < 24:
            return info
        sizes = {24: (1, 24), 25: (2, 0x100), 26: (4, 0x10000), 27: (8, 0x100000000)}
        if info == 31:
            raise CanonicalError("indefinite lengths are not permitted")
        if info not in sizes:
            raise CanonicalError("unsupported item")
        size, minimum = sizes[info]
        n = int.from_bytes(take(size), "big")
        if n < minimum:
            raise CanonicalError("non-shortest encoding")
        return n

    def text(info: int) -> str:
        n = arg(info)
        try:
            return take(n).decode("utf-8")
        except UnicodeDecodeError as e:
            raise CanonicalError("invalid UTF-8") from e

    def value(depth: int):
        nonlocal pos
        if depth > MAX_DEPTH:
            raise CanonicalError("nesting too deep")
        ib = take(1)[0]
        major, info = ib >> 5, ib & 0x1F
        if major == 0:
            n = arg(info)
            if n > MAX_SAFE:
                raise CanonicalError("integer outside the canonical range")
            return n
        if major == 1:
            n = arg(info)
            if n >= MAX_SAFE:
                raise CanonicalError("integer outside the canonical range")
            return -1 - n
        if major == 3:
            return text(info)
        if major == 4:
            n = arg(info)
            if n > len(data) - pos:
                raise CanonicalError("truncated")
            return [value(depth + 1) for _ in range(n)]
        if major == 5:
            n = arg(info)
            if n > len(data) - pos:
                raise CanonicalError("truncated")
            out = {}
            prev = None
            for _ in range(n):
                start = pos
                kb = take(1)[0]
                if kb >> 5 != 3:
                    raise CanonicalError("map keys must be text")
                key = text(kb & 0x1F)
                raw = data[start:pos]
                if prev is not None and prev >= raw:
                    raise CanonicalError("map keys unsorted or duplicated")
                prev = raw
                out[key] = value(depth + 1)
            return out
        if major == 7:
            if info == 20:
                return False
            if info == 21:
                return True
            raise CanonicalError("null, undefined and floats are not permitted" if info in (22, 23, 25, 26, 27) else "unsupported simple value")
        raise CanonicalError("indefinite lengths are not permitted" if info == 31 else "unsupported CBOR major type")

    v = value(0)
    if pos != len(data):
        raise CanonicalError("trailing bytes")
    return v


def prune(v):
    """Removes None fields (absent values are omitted, never null)."""
    if isinstance(v, dict):
        return {k: prune(val) for k, val in v.items() if val is not None}
    if isinstance(v, list):
        return [prune(x) for x in v]
    return v
