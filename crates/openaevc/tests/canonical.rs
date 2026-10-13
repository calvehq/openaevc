use openaevc::canonical::{decode, encode, from_canonical, to_canonical, CanonicalError};
use proptest::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn integers_use_shortest_form() {
    assert_eq!(hex(&encode(&json!(0)).unwrap()), "00");
    assert_eq!(hex(&encode(&json!(23)).unwrap()), "17");
    assert_eq!(hex(&encode(&json!(24)).unwrap()), "1818");
    assert_eq!(hex(&encode(&json!(256)).unwrap()), "190100");
    assert_eq!(hex(&encode(&json!(65536)).unwrap()), "1a00010000");
    assert_eq!(
        hex(&encode(&json!(4294967296u64)).unwrap()),
        "1b0000000100000000"
    );
    assert_eq!(hex(&encode(&json!(-1)).unwrap()), "20");
    assert_eq!(hex(&encode(&json!(-25)).unwrap()), "3818");
}

#[test]
fn map_keys_sorted_by_encoded_bytes() {
    // Length-first then bytewise: "b" < "aa".
    let v = json!({"aa": 1, "b": 2, "a": 3});
    assert_eq!(
        hex(&encode(&v).unwrap()),
        "a3616103616202626161 01".replace(' ', "")
    );
}

#[test]
fn text_bool_array() {
    assert_eq!(hex(&encode(&json!("é")).unwrap()), "62c3a9");
    assert_eq!(hex(&encode(&json!([true, false])).unwrap()), "82f5f4");
}

#[test]
fn rejects_floats_nulls_and_unsafe_integers() {
    assert!(matches!(encode(&json!(1.5)), Err(CanonicalError::Float)));
    assert!(matches!(encode(&json!(1.0)), Err(CanonicalError::Float)));
    assert!(matches!(
        encode(&json!({"a": null})),
        Err(CanonicalError::Null)
    ));
    assert!(matches!(
        encode(&json!(9007199254740992u64)),
        Err(CanonicalError::IntegerRange)
    ));
    assert!(matches!(
        encode(&json!(-9007199254740992i64)),
        Err(CanonicalError::IntegerRange)
    ));
    assert!(encode(&json!(9007199254740991u64)).is_ok());
}

#[test]
fn decode_round_trips() {
    let v = json!({"k": [1, -2, "x", {"n": true}], "z": 70000});
    assert_eq!(decode(&encode(&v).unwrap()).unwrap(), v);
}

fn bytes(h: &str) -> Vec<u8> {
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn decode_rejects_non_canonical_inputs() {
    for (h, why) in [
        ("1817", "non-shortest integer"),
        ("190017", "non-shortest integer"),
        ("5f4100ff", "indefinite byte string"),
        ("9f01ff", "indefinite array"),
        ("a2616201616101", "unsorted map keys"),
        ("a2616101616102", "duplicate map keys"),
        ("f97e00", "float"),
        ("f6", "null"),
        ("f7", "undefined"),
        ("c001", "tag"),
        ("4100", "byte string"),
        ("a10101", "non-text map key"),
        ("62c3", "truncated"),
        ("0000", "trailing bytes"),
        ("61ff", "invalid utf-8"),
        ("1b0020000000000000", "integer out of safe range"),
        ("", "empty"),
    ] {
        assert!(decode(&bytes(h)).is_err(), "{why}: {h} accepted");
    }
}

#[test]
fn decode_limits_nesting_depth() {
    let mut deep = vec![0x81u8; 200];
    deep.push(0x00);
    assert!(matches!(decode(&deep), Err(CanonicalError::TooDeep)));
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Obj {
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    count: Option<u32>,
}

#[test]
fn typed_round_trip_and_unknown_fields_rejected() {
    let o = Obj {
        name: "x".into(),
        count: None,
    };
    let b = to_canonical(&o).unwrap();
    assert_eq!(from_canonical::<Obj>(&b).unwrap(), o);
    let extra = encode(&json!({"name": "x", "zzz": 1})).unwrap();
    assert!(from_canonical::<Obj>(&extra).is_err());
}

#[test]
fn typed_decode_rejects_values_lost_in_round_trip() {
    #[derive(Debug, Serialize, Deserialize)]
    struct Lenient {
        name: String,
    }
    // A lenient type would silently drop "zzz"; from_canonical must refuse because the
    // re-encoding differs from the input bytes.
    let extra = encode(&json!({"name": "x", "zzz": 1})).unwrap();
    assert!(from_canonical::<Lenient>(&extra).is_err());
}

fn arb_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        any::<bool>().prop_map(Value::from),
        (-(1i64 << 53) + 1..(1i64 << 53)).prop_map(Value::from),
        ".{0,8}".prop_map(Value::from),
    ];
    leaf.prop_recursive(4, 32, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::from),
            prop::collection::btree_map(".{0,6}", inner, 0..6)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

proptest! {
    #[test]
    fn prop_round_trip(v in arb_json()) {
        let b = encode(&v).unwrap();
        prop_assert_eq!(decode(&b).unwrap(), v.clone());
        prop_assert_eq!(encode(&decode(&b).unwrap()).unwrap(), b);
    }

    #[test]
    fn prop_key_order_independent(m in prop::collection::btree_map(".{0,6}", any::<i32>(), 0..8)) {
        let fwd: serde_json::Map<String, Value> = m.iter().map(|(k, v)| (k.clone(), Value::from(*v))).collect();
        let rev: serde_json::Map<String, Value> = m.iter().rev().map(|(k, v)| (k.clone(), Value::from(*v))).collect();
        prop_assert_eq!(encode(&Value::Object(fwd)).unwrap(), encode(&Value::Object(rev)).unwrap());
    }

    #[test]
    fn prop_decode_never_panics(b in prop::collection::vec(any::<u8>(), 0..64)) {
        let _ = decode(&b);
    }
}
