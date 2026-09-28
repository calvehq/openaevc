// Deterministic CBOR of the JSON data model (spec/canonical-encoding.md).
// Integers within ±(2^53-1), text keys sorted by encoded bytes, definite lengths,
// no floats/null/tags/byte strings. Decoding is strict.

export type Json = boolean | number | string | Json[] | { [key: string]: Json };

export class CanonicalError extends Error {}

const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true });

function head(out: number[], major: number, n: number): void {
  const m = major << 5;
  if (n < 24) out.push(m | n);
  else if (n <= 0xff) out.push(m | 24, n);
  else if (n <= 0xffff) out.push(m | 25, n >> 8, n & 0xff);
  else if (n <= 0xffffffff) out.push(m | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
  else {
    const hi = Math.floor(n / 0x100000000);
    const lo = n >>> 0;
    out.push(m | 27, 0, (hi >>> 16) & 0xff, (hi >>> 8) & 0xff, hi & 0xff, (lo >>> 24) & 0xff, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff);
  }
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

function encodeInto(v: Json, out: number[]): void {
  if (v === null || v === undefined) throw new CanonicalError("null is not permitted in canonical objects");
  if (typeof v === "boolean") out.push(v ? 0xf5 : 0xf4);
  else if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new CanonicalError("floating-point values are not permitted");
    if (!Number.isSafeInteger(v)) throw new CanonicalError("integer outside ±(2^53-1)");
    if (v >= 0) head(out, 0, v);
    else head(out, 1, -1 - v);
  } else if (typeof v === "string") {
    // A lone surrogate would silently become U+FFFD: the signed value would differ from v.
    if (!/^(?:[^\uD800-\uDFFF]|[\uD800-\uDBFF][\uDC00-\uDFFF])*$/.test(v))
      throw new CanonicalError("text is not valid Unicode (lone surrogate)");
    const b = enc.encode(v);
    head(out, 3, b.length);
    for (const x of b) out.push(x);
  } else if (Array.isArray(v)) {
    head(out, 4, v.length);
    for (const item of v) encodeInto(item, out);
  } else if (typeof v !== "object" || (Object.getPrototypeOf(v) !== Object.prototype && Object.getPrototypeOf(v) !== null)) {
    // Byte arrays, Maps, class instances, bigints, functions: not in the JSON data model.
    throw new CanonicalError("only plain objects, arrays, strings, integers and booleans are canonical");
  } else {
    const entries = Object.entries(v).map(([k, val]) => {
      const kb: number[] = [];
      encodeInto(k, kb);
      return [Uint8Array.from(kb), val] as const;
    });
    entries.sort((a, b) => compareBytes(a[0], b[0]));
    head(out, 5, entries.length);
    for (const [k, val] of entries) {
      for (const x of k) out.push(x);
      encodeInto(val, out);
    }
  }
}

export function encode(v: Json): Uint8Array {
  const out: number[] = [];
  encodeInto(v, out);
  return Uint8Array.from(out);
}

export function decode(bytes: Uint8Array): Json {
  let pos = 0;
  const take = (n: number): Uint8Array => {
    if (pos + n > bytes.length) throw new CanonicalError("truncated");
    const s = bytes.subarray(pos, pos + n);
    pos += n;
    return s;
  };
  const arg = (info: number): number => {
    let n: number;
    let min: number;
    if (info < 24) return info;
    if (info === 24) [n, min] = [take(1)[0], 24];
    else if (info === 25) {
      const b = take(2);
      [n, min] = [(b[0] << 8) | b[1], 0x100];
    } else if (info === 26) {
      const b = take(4);
      [n, min] = [((b[0] << 24) >>> 0) + (b[1] << 16) + (b[2] << 8) + b[3], 0x10000];
    } else if (info === 27) {
      const b = take(8);
      const hi = ((b[0] << 24) >>> 0) + (b[1] << 16) + (b[2] << 8) + b[3];
      const lo = ((b[4] << 24) >>> 0) + (b[5] << 16) + (b[6] << 8) + b[7];
      if (hi > 0x1fffff) throw new CanonicalError("integer outside the canonical range");
      [n, min] = [hi * 0x100000000 + lo, 0x100000000];
    } else if (info === 31) throw new CanonicalError("indefinite lengths are not permitted");
    else throw new CanonicalError("unsupported item");
    if (n < min) throw new CanonicalError("non-shortest encoding");
    return n;
  };
  const value = (depth: number): Json => {
    if (depth > 128) throw new CanonicalError("nesting too deep");
    const ib = take(1)[0];
    const major = ib >> 5;
    const info = ib & 0x1f;
    switch (major) {
      case 0: {
        const n = arg(info);
        if (n > Number.MAX_SAFE_INTEGER) throw new CanonicalError("integer outside the canonical range");
        return n;
      }
      case 1: {
        const n = arg(info);
        if (n >= Number.MAX_SAFE_INTEGER) throw new CanonicalError("integer outside the canonical range");
        return -1 - n;
      }
      case 3: {
        const len = arg(info);
        try {
          return dec.decode(take(len));
        } catch (e) {
          if (e instanceof CanonicalError) throw e;
          throw new CanonicalError("invalid UTF-8");
        }
      }
      case 4: {
        const len = arg(info);
        if (len > bytes.length - pos) throw new CanonicalError("truncated");
        const a: Json[] = [];
        for (let i = 0; i < len; i++) a.push(value(depth + 1));
        return a;
      }
      case 5: {
        const len = arg(info);
        if (len > bytes.length - pos) throw new CanonicalError("truncated");
        const m: { [key: string]: Json } = {};
        let prev: Uint8Array | undefined;
        for (let i = 0; i < len; i++) {
          const start = pos;
          const kb = take(1)[0];
          if (kb >> 5 !== 3) throw new CanonicalError("map keys must be text");
          const klen = arg(kb & 0x1f);
          let key: string;
          try {
            key = dec.decode(take(klen));
          } catch (e) {
            if (e instanceof CanonicalError) throw e;
            throw new CanonicalError("invalid UTF-8");
          }
          const raw = bytes.subarray(start, pos);
          if (prev && compareBytes(prev, raw) >= 0) throw new CanonicalError("map keys unsorted or duplicated");
          prev = raw;
          Object.defineProperty(m, key, { value: value(depth + 1), enumerable: true, writable: true, configurable: true });
        }
        return m;
      }
      case 7:
        if (info === 20) return false;
        if (info === 21) return true;
        throw new CanonicalError(info === 22 ? "null is not permitted" : "unsupported simple value or float");
      default:
        throw new CanonicalError(info === 31 ? "indefinite lengths are not permitted" : "unsupported CBOR major type");
    }
  };
  const v = value(0);
  if (pos !== bytes.length) throw new CanonicalError("trailing bytes");
  return v;
}

/** Removes `undefined`/`null` fields (absent values are omitted, never null). */
export function prune(v: unknown): Json {
  if (Array.isArray(v)) return v.map(prune);
  if (v !== null && typeof v === "object") {
    const out: { [key: string]: Json } = {};
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
      if (val === undefined || val === null) continue;
      out[k] = prune(val);
    }
    return out;
  }
  return v as Json;
}
