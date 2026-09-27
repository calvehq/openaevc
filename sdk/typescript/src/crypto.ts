// SHA-256 digests and Ed25519 signatures with OpenAEVC domain separation.
import { createHash, createPrivateKey, createPublicKey, sign as edSign, verify as edVerify, randomBytes } from "node:crypto";
import { encode, type Json } from "./canonical.ts";

export type Domain = "request" | "grant" | "object" | "checkpoint" | "receipt";

export function sha256(bytes: Uint8Array): string {
  return "sha256:" + createHash("sha256").update(bytes).digest("hex");
}

export function digestOf(v: Json): string {
  return sha256(encode(v));
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

export function verify(publicKey: string, domain: Domain, message: Uint8Array, signature: string): boolean {
  const raw = fromB64url(publicKey.replace(/^ed25519:/, ""));
  const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
  const key = createPublicKey({ key: spki, format: "der", type: "spki" });
  return edVerify(null, domainMessage(domain, message), key, fromB64url(signature));
}
