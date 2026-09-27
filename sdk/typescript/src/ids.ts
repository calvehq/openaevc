// Typed identifiers: `<prefix>_<base32(uuidv7)>`.
import { randomBytes } from "node:crypto";
import { ID_PREFIXES } from "./generated.ts";

const ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";

export function base32(bytes: Uint8Array): string {
  let out = "";
  let acc = 0;
  let bits = 0;
  for (const b of bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET[(acc >>> bits) & 31];
    }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) out += ALPHABET[(acc << (5 - bits)) & 31];
  return out;
}

export function uuidv7(nowMs: number = Date.now()): Uint8Array {
  const b = new Uint8Array(16);
  let ms = nowMs;
  for (let i = 5; i >= 0; i--) {
    b[i] = ms % 256;
    ms = Math.floor(ms / 256);
  }
  b.set(randomBytes(10), 6);
  b[6] = 0x70 | (b[6] & 0x0f);
  b[8] = 0x80 | (b[8] & 0x3f);
  return b;
}

export function newId(prefix: string): string {
  return `${prefix}_${base32(uuidv7())}`;
}

const ID_RE = /^([a-z]{2,3})_([a-z2-7]{26})$/;

/** Validates a typed ID (case-insensitive input) and returns its canonical lowercase form. */
export function parseId(text: string, prefix?: string): string {
  const lower = text.toLowerCase();
  const m = ID_RE.exec(lower);
  if (!m || !(ID_PREFIXES as readonly string[]).includes(m[1]) || (prefix && m[1] !== prefix)) throw new Error(`invalid identifier ${text}`);
  const body = m[2];
  let acc = 0;
  let bits = 0;
  const bytes: number[] = [];
  for (const ch of body) {
    acc = (acc << 5) | ALPHABET.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((acc >>> bits) & 0xff);
    }
    acc &= (1 << bits) - 1;
  }
  if (acc !== 0) throw new Error(`invalid identifier ${text}: non-zero trailing bits`);
  if (bytes[6] >> 4 !== 7 || bytes[8] >> 6 !== 2) throw new Error(`invalid identifier ${text}: not a UUIDv7`);
  return lower;
}
