// SHA-256 digests and Ed25519 signatures with OpenAEVC domain separation.
import { createHash, createPrivateKey, createPublicKey, sign as edSign, verify as edVerify, randomBytes } from "node:crypto";
import { encode, type Json } from "./canonical.ts";

export type Domain = "request" | "grant" | "object";

export function sha256(bytes: Uint8Array): string {
  return "sha256:" + createHash("sha256").update(bytes).digest("hex");
}

export function digestOf(v: Json): string {
  return sha256(encode(v));
}

/**
 * Signing digest of an immutable-object envelope: SHA-256 of its canonical encoding without
 * `signatures`. Object signatures are over its 32 raw bytes in the `object` domain; references
 * use the object digest, `digestOf(envelope)` (spec/identity-and-digests.md).
 */
export function signingDigest(envelope: { [k: string]: Json }): string {
  const { signatures: _omitted, ...unsigned } = envelope;
  return digestOf(unsigned as Json);
}

export function b64url(b: Uint8Array): string {
  return Buffer.from(b).toString("base64url");
}

export function fromB64url(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}

const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

/** An Ed25519 key held in memory, created from its 32-byte seed. */
export class SigningKey {
  readonly seed: Uint8Array;
  readonly publicKey: string;
  #key: ReturnType<typeof createPrivateKey>;

  constructor(seed: Uint8Array) {
    if (seed.length !== 32) throw new Error("Ed25519 seed must be 32 bytes");
    this.seed = seed;
    this.#key = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed]), format: "der", type: "pkcs8" });
    const spki = createPublicKey(this.#key).export({ format: "der", type: "spki" }) as Buffer;
    this.publicKey = "ed25519:" + b64url(spki.subarray(spki.length - 32));
  }

  static generate(): SigningKey {
    return new SigningKey(new Uint8Array(randomBytes(32)));
  }

  static fromHex(hex: string): SigningKey {
    return new SigningKey(new Uint8Array(Buffer.from(hex.trim(), "hex")));
  }

  sign(domain: Domain, message: Uint8Array): string {
    return b64url(edSign(null, domainMessage(domain, message), this.#key));
  }
}

function domainMessage(domain: Domain, message: Uint8Array): Buffer {
  return Buffer.concat([Buffer.from(`OPENAEVC/1 ${domain}\n`), message]);
}

/** Canonical unpadded base64url of exactly `n` bytes, or undefined. */
function strictB64(s: string, n: number): Uint8Array | undefined {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s)) return undefined;
  const b = fromB64url(s);
  return b.length === n && b64url(b) === s ? b : undefined;
}

// Encodings (sign bit cleared) of points of small order, canonical or not (as in libsodium).
const SMALL_ORDER = new Set([
  "00".repeat(32),
  "01" + "00".repeat(31),
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "ec" + "ff".repeat(30) + "7f",
  "ed" + "ff".repeat(30) + "7f",
  "ee" + "ff".repeat(30) + "7f",
]);
const P = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const le = (b: Uint8Array) => b.reduceRight((acc, x) => (acc << 8n) | BigInt(x), 0n);

function weakPoint(enc: Uint8Array): boolean {
  const c = Uint8Array.from(enc);
  c[31] &= 0x7f;
  return SMALL_ORDER.has(Buffer.from(c).toString("hex")) || le(c) >= P;
}

/** Strict Ed25519 (AEVC-ID-0006): canonical encodings, no small-order key or R, S < L. */
export function verify(publicKey: string, domain: Domain, message: Uint8Array, signature: string): boolean {
  if (typeof publicKey !== "string" || !publicKey.startsWith("ed25519:")) return false;
  const raw = strictB64(publicKey.slice("ed25519:".length), 32);
  const sig = strictB64(signature, 64);
  if (!raw || !sig || weakPoint(raw) || weakPoint(sig.subarray(0, 32)) || le(sig.subarray(32)) >= L) return false;
  const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
  const key = createPublicKey({ key: spki, format: "der", type: "spki" });
  return edVerify(null, domainMessage(domain, message), key, sig);
}
