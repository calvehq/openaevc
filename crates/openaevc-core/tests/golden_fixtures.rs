//! Golden canonical fixtures (fixtures/canonical) shared by every SDK.

use std::path::PathBuf;

use openaevc_core::ImmutableObject;
use openaevc_protocol::{Digest, PublicKey};
use serde_json::Value;

fn load(name: &str) -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/canonical").join(name);
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p:?}: {e}"))).unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn values_encode_to_golden_bytes_and_digests() {
    let f = load("values.json");
    let cases = f["valid"].as_array().unwrap();
    assert!(cases.len() >= 10);
    for c in cases {
        let bytes = openaevc_canonical::encode(&c["json"]).unwrap();
        assert_eq!(hex(&bytes), c["cbor_hex"], "{}", c["name"]);
        assert_eq!(openaevc_crypto::sha256(&bytes).to_string(), c["digest"], "{}", c["name"]);
        assert_eq!(openaevc_canonical::decode(&bytes).unwrap(), c["json"], "{}", c["name"]);
    }
    for c in f["invalid_cbor"].as_array().unwrap() {
        assert!(openaevc_canonical::decode(&unhex(c["cbor_hex"].as_str().unwrap())).is_err(), "{}", c["name"]);
    }
    for c in f["invalid_json"].as_array().unwrap() {
        assert!(openaevc_canonical::encode(&c["json"]).is_err(), "{}", c["name"]);
    }
}

#[test]
fn every_object_kind_has_a_golden_fixture() {
    let f = load("objects.json");
    let cases = f["valid"].as_array().unwrap();
    let mut kinds: Vec<&str> = cases.iter().map(|c| c["kind"].as_str().unwrap()).collect();
    kinds.sort();
    kinds.dedup();
    assert_eq!(kinds.len(), openaevc_protocol::ObjectKind::ALL.len());
    for c in cases {
        let bytes = unhex(c["cbor_hex"].as_str().unwrap());
        let digest: Digest = c["digest"].as_str().unwrap().parse().unwrap();
        let obj = ImmutableObject::from_bytes(&bytes, Some(digest)).unwrap();
        assert_eq!(openaevc_canonical::to_value(obj.envelope()).unwrap(), c["json"], "{}", c["name"]);
        let refs: Vec<String> = obj.references().unwrap().iter().map(|d| d.to_string()).collect();
        let want: Vec<String> = serde_json::from_value(c["references"].clone()).unwrap();
        assert_eq!(refs, want, "{}", c["name"]);
    }
    for c in f["invalid"].as_array().unwrap() {
        let bytes = unhex(c["cbor_hex"].as_str().unwrap());
        let expected = c.get("digest").and_then(Value::as_str).map(|d| d.parse().unwrap());
        let e = ImmutableObject::from_bytes(&bytes, expected).unwrap_err();
        assert_eq!(e.code.as_str(), c["error"], "{}", c["name"]);
    }
}

#[test]
fn signature_fixtures_are_reproducible() {
    let f = load("signatures.json");
    for c in f["cases"].as_array().unwrap() {
        let seed: [u8; 32] = unhex(c["seed_hex"].as_str().unwrap()).try_into().unwrap();
        let key = openaevc_crypto::SigningKey::from_seed(seed);
        use openaevc_crypto::Signer;
        let pk: PublicKey = c["public_key"].as_str().unwrap().parse().unwrap();
        assert_eq!(key.public_key(), pk);
        let msg = openaevc_canonical::encode(&c["unsigned"]).unwrap();
        assert_eq!(hex(&msg), c["message_hex"]);
        let domain = match c["domain"].as_str().unwrap() {
            "request" => openaevc_crypto::Domain::Request,
            "grant" => openaevc_crypto::Domain::Grant,
            other => panic!("{other}"),
        };
        assert_eq!(key.sign(domain, &msg).to_string(), c["signature"]);
    }
}

#[test]
fn identifier_fixtures() {
    let f = load("identifiers.json");
    for s in f["valid"].as_array().unwrap() {
        let s = s.as_str().unwrap();
        let ok = s.parse::<openaevc_protocol::AnyId>().map(|_| ()).is_ok()
            || s.parse::<Digest>().is_ok()
            || s.parse::<openaevc_protocol::Timestamp>().is_ok();
        assert!(ok, "{s}");
    }
    for s in f["invalid"].as_array().unwrap() {
        let s = s.as_str().unwrap();
        assert!(s.parse::<openaevc_protocol::AnyId>().is_err() && s.parse::<Digest>().is_err()
            && s.parse::<openaevc_protocol::Timestamp>().is_err(), "{s}");
    }
}
