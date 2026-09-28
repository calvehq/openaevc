"""Cross-SDK golden fixtures."""
import hashlib
import json
import pathlib
import unittest

from openaevc import crypto
from openaevc.canonical import CanonicalError, decode, encode
from openaevc.ids import new_id, parse_id

FIX = pathlib.Path(__file__).resolve().parents[3] / "fixtures"


def load(name):
    return json.loads((FIX / name).read_text())


class Canonical(unittest.TestCase):
    def test_values(self):
        f = load("canonical/values.json")
        for c in f["valid"]:
            b = encode(c["json"])
            self.assertEqual(b.hex(), c["cbor_hex"], c["name"])
            self.assertEqual(crypto.sha256(b), c["digest"], c["name"])
            self.assertEqual(decode(b), c["json"], c["name"])
        for c in f["invalid_cbor"]:
            with self.assertRaises(CanonicalError, msg=c["name"]):
                decode(bytes.fromhex(c["cbor_hex"]))
        for c in f["invalid_json"]:
            with self.assertRaises(CanonicalError, msg=c["name"]):
                encode(c["json"])

    def test_objects(self):
        for c in load("canonical/objects.json")["valid"]:
            b = bytes.fromhex(c["cbor_hex"])
            self.assertEqual(crypto.sha256(b), c["digest"], c["name"])
            self.assertEqual(decode(b), c["json"], c["name"])
            self.assertEqual(encode(c["json"]).hex(), c["cbor_hex"], c["name"])
            if "signing_digest" in c:
                # Object digest covers the signatures; each signature covers the signing digest.
                unsigned = {k: v for k, v in c["json"].items() if k != "signatures"}
                sd = encode(unsigned)
                self.assertEqual(crypto.sha256(sd), c["signing_digest"], c["name"])
                self.assertEqual(crypto.signing_digest(c["json"]), c["signing_digest"], c["name"])
                for s in c["json"]["signatures"]:
                    msg = hashlib.sha256(sd).digest()
                    self.assertTrue(crypto.verify(s["public_key"], "object", msg, s["signature"]))


class Signatures(unittest.TestCase):
    def test_signature_fixtures(self):
        for c in load("canonical/signatures.json")["cases"]:
            key = crypto.SigningKey(bytes.fromhex(c["seed_hex"]))
            self.assertEqual(key.public_key, c["public_key"])
            msg = encode(c["unsigned"])
            if c["domain"] == "object":
                msg = hashlib.sha256(msg).digest()
            self.assertEqual(msg.hex(), c["message_hex"])
            self.assertEqual(key.sign(c["domain"], msg), c["signature"])
            self.assertTrue(crypto.verify(c["public_key"], c["domain"], msg, c["signature"]))
            other = "grant" if c["domain"] == "request" else "request"
            self.assertFalse(crypto.verify(c["public_key"], other, msg, c["signature"]))

    def test_invalid_signatures_rejected(self):
        for c in load("canonical/signatures.json")["invalid"]:
            msg = bytes.fromhex(c["message_hex"])
            self.assertFalse(crypto.verify(c["public_key"], c["domain"], msg, c["signature"]), c["name"])

    def test_pure_python_ed25519_matches(self):
        from openaevc import ed25519
        c = load("canonical/signatures.json")["cases"][0]
        seed = bytes.fromhex(c["seed_hex"])
        msg = b"OPENAEVC/1 request\n" + encode(c["unsigned"])
        sig = ed25519.sign(seed, msg)
        self.assertEqual(crypto.b64url(sig), c["signature"])
        self.assertTrue(ed25519.verify(ed25519.public_key(seed), msg, sig))


class Identifiers(unittest.TestCase):
    def test_identifier_fixtures(self):
        f = load("canonical/identifiers.json")
        for s in f["valid"]:
            if "_" in s and not s.startswith("sha256"):
                self.assertEqual(parse_id(s), s.lower())
        for s in f["invalid"]:
            if "_" in s and not s.startswith("sha256"):
                with self.assertRaises(ValueError, msg=s):
                    parse_id(s)
        i = new_id("cpk")
        self.assertEqual(parse_id(i, "cpk"), i)


if __name__ == "__main__":
    unittest.main()
