// Cross-SDK golden fixtures: every SDK must reproduce the same bytes, digests and signatures.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { encode, decode, type Json } from "../src/canonical.ts";
import { sha256, SigningKey, verify } from "../src/crypto.ts";
import { parseId, newId } from "../src/ids.ts";

const root = new URL("../../../fixtures/", import.meta.url);
const load = (name: string) => JSON.parse(readFileSync(new URL(name, root), "utf8"));
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const unhex = (s: string) => new Uint8Array(Buffer.from(s, "hex"));

test("canonical values encode to golden bytes and digests", () => {
  const f = load("canonical/values.json");
  for (const c of f.valid) {
    const bytes = encode(c.json as Json);
    assert.equal(hex(bytes), c.cbor_hex, c.name);
    assert.equal(sha256(bytes), c.digest, c.name);
    assert.deepEqual(decode(bytes), c.json, c.name);
  }
  for (const c of f.invalid_cbor) assert.throws(() => decode(unhex(c.cbor_hex)), Error, c.name);
    // JavaScript cannot distinguish 2.0 from 2; such cases only bind SDKs whose JSON model can.
  for (const c of f.invalid_json) if (!c.requires_float_distinction) assert.throws(() => encode(c.json as Json), Error, c.name);
});

test("object fixtures decode, re-encode and hash identically", () => {
  const f = load("canonical/objects.json");
  for (const c of f.valid) {
    const bytes = unhex(c.cbor_hex);
    assert.equal(sha256(bytes), c.digest, c.name);
    assert.deepEqual(decode(bytes), c.json, c.name);
    assert.equal(hex(encode(c.json)), c.cbor_hex, c.name);
  }
});

test("signature fixtures are reproducible", () => {
  const f = load("canonical/signatures.json");
  for (const c of f.cases) {
    const key = new SigningKey(unhex(c.seed_hex));
    assert.equal(key.publicKey, c.public_key);
    const msg = encode(c.unsigned);
    assert.equal(hex(msg), c.message_hex);
    assert.equal(key.sign(c.domain, msg), c.signature);
    assert.ok(verify(c.public_key, c.domain, msg, c.signature));
    assert.ok(!verify(c.public_key, c.domain === "grant" ? "request" : "grant", msg, c.signature));
  }
});

test("identifiers", () => {
  const f = load("canonical/identifiers.json");
  for (const s of f.valid) if (/^[a-z]{2,3}_/i.test(s)) assert.equal(parseId(s), s.toLowerCase());
  for (const s of f.invalid) if (/^[a-z]{2,3}_/i.test(s)) assert.throws(() => parseId(s), Error, s);
  const id = newId("cpk");
  assert.equal(parseId(id, "cpk"), id);
});
