//! CORE profile: canonical encoding, identity, digests, signatures, errors, versions — all
//! observed through the public API.

use openaevc_protocol::*;
use openaevc_sdk::{OpenAevcClient, TypedClient};
use serde_json::{json, Value};

use crate::ctx::{ensure, expect_code, fixtures, unhex, Check, Ctx};
use crate::CaseResult;

async fn import(
    cx: &Ctx,
    ns: &crate::ctx::Ns,
    digest: Digest,
    bytes: Vec<u8>,
) -> Result<CommandReceipt, ProtocolError> {
    let env = cx
        .envelope_value(
            &ns.root_key,
            ns.root_id,
            Some(ns.id),
            Command::PutImmutableObject {
                digest,
                bytes: vec![],
            },
        )
        .map_err(err::internal)?;
    cx.target.put_object_payload(env, digest, bytes).await
}

pub async fn objects_round_trip(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let f = fixtures("objects")?;
    for c in f["valid"].as_array().ok_or("fixtures")? {
        let bytes = unhex(c["cbor_hex"].as_str().ok_or("hex")?);
        let digest: Digest = c["digest"]
            .as_str()
            .ok_or("digest")?
            .parse()
            .map_err(|_| "digest")?;
        ensure(openaevc_crypto::sha256(&bytes) == digest, "fixture digest")?;
        import(cx, &ns, digest, bytes.clone()).await.c()?;
        let back = ns.root.get_object(digest).await.c()?;
        ensure(
            back.bytes() == bytes.as_slice(),
            format!("{}: object bytes changed", c["name"]),
        )?;
        // Re-import of a present object is a no-op.
        import(cx, &ns, digest, bytes).await.c()?;
    }
    let events = cx.events(&ns.root).await?;
    ensure(
        events
            .iter()
            .any(|e| e.kind == "object.imported" && e.body["already_present"] == true),
        "re-import must be recorded as a no-op",
    )
}

pub async fn objects_invalid_rejected(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let f = fixtures("objects")?;
    for c in f["invalid"].as_array().ok_or("fixtures")? {
        let bytes = unhex(c["cbor_hex"].as_str().ok_or("hex")?);
        let digest = match c.get("digest").and_then(Value::as_str) {
            Some(d) => d.parse().map_err(|_| "digest")?,
            None => openaevc_crypto::sha256(&bytes),
        };
        let want: ErrorCode =
            serde_json::from_value(c["error"].clone()).map_err(|e| e.to_string())?;
        expect_code(import(cx, &ns, digest, bytes).await, want)
            .map_err(|e| format!("{}: {e}", c["name"]))?;
    }
    // Every non-canonical encoding of the golden set is refused by the target's decoder.
    for c in fixtures("values")?["invalid_cbor"]
        .as_array()
        .ok_or("fixtures")?
    {
        let bytes = unhex(c["cbor_hex"].as_str().ok_or("hex")?);
        expect_code(
            import(cx, &ns, openaevc_crypto::sha256(&bytes), bytes).await,
            ErrorCode::CanonicalEncodingError,
        )
        .map_err(|e| format!("invalid CBOR {}: {e}", c["name"]))?;
    }
    Ok(())
}

/// Object identity covers the signature set; every signature covers the same signing digest.
pub async fn signature_identity(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let f = fixtures("objects")?;
    let two = f["valid"]
        .as_array()
        .ok_or("fixtures")?
        .iter()
        .find(|c| c["name"] == "blob_two_signatures")
        .ok_or("blob_two_signatures fixture")?;
    let mut unsigned = two["json"].clone();
    let sigs = unsigned
        .as_object_mut()
        .ok_or("object")?
        .remove("signatures")
        .and_then(|s| s.as_array().cloned())
        .ok_or("signatures")?;
    let enc = |v: &Value| openaevc_canonical::encode(v).map_err(|e| e.to_string());
    ensure(
        openaevc_crypto::sha256(&enc(&unsigned)?).to_string() == two["signing_digest"],
        "signing digest is SHA-256 of the envelope without signatures",
    )?;
    // Every subset of a valid signature set is a valid, distinct object.
    let mut one = unsigned.clone();
    one["signatures"] = json!([sigs[0]]);
    let mut seen = std::collections::BTreeSet::new();
    for v in [unsigned.clone(), one, two["json"].clone()] {
        let bytes = enc(&v)?;
        let digest = openaevc_crypto::sha256(&bytes);
        import(cx, &ns, digest, bytes.clone()).await.c()?;
        let back = ns.root.get_object(digest).await.c()?;
        ensure(back.bytes() == bytes.as_slice(), "object bytes changed")?;
        ensure(
            seen.insert(digest),
            "signature sets must yield distinct object digests",
        )?;
    }
    // Signing order has no effect: only the canonical (sorted) order is accepted.
    let mut reversed = two["json"].clone();
    reversed["signatures"] = json!(sigs.iter().rev().collect::<Vec<_>>());
    let bytes = enc(&reversed)?;
    expect_code(
        import(cx, &ns, openaevc_crypto::sha256(&bytes), bytes).await,
        ErrorCode::CanonicalEncodingError,
    )
    .map(drop)
}

pub async fn envelope_data_model(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let cases = [
        json!({"type": "CreateChangePack", "spec": {"metadata": {"org.x.n": 1.5}}}),
        json!({"type": "CreateChangePack", "spec": {"intent": null}}),
        json!({"type": "CreateChangePack", "spec": {"metadata": {"org.x.n": 9007199254740992u64}}}),
    ];
    for body in cases {
        let v = cx.signed_value(&ns.root_key, ns.root_id, Some(ns.id), body.clone(), |_| {});
        let e = cx.target.command_value(v).await;
        match e {
            Err(e)
                if matches!(
                    e.code,
                    ErrorCode::CanonicalEncodingError | ErrorCode::InvalidArgument
                ) => {}
            other => return Err(format!("{body}: expected rejection, got {other:?}")),
        }
    }
    Ok(())
}

pub async fn key_order(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let v = cx.signed_value(
        &ns.root_key,
        ns.root_id,
        Some(ns.id),
        json!({"type": "CreateChangePack", "spec": {}}),
        |_| {},
    );
    // Re-order keys; the canonical encoding (and so the signature) is unaffected.
    let mut reversed = serde_json::Map::new();
    for (k, val) in v.as_object().ok_or("object")?.iter().rev() {
        reversed.insert(k.clone(), val.clone());
    }
    cx.target
        .command_value(Value::Object(reversed))
        .await
        .c()
        .map(drop)
}

pub async fn text_byte_exact(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let (nfc, nfd) = ("\u{e9}", "e\u{301}");
    let spec = PackSpec {
        metadata: [
            ("org.x.nfc".to_string(), json!(nfc)),
            ("org.x.nfd".to_string(), json!(nfd)),
        ]
        .into_iter()
        .collect(),
        ..Default::default()
    };
    let pack = ns.root.create_change_pack(spec).await.c()?;
    let p = ns.root.get_change_pack(pack).await.c()?;
    ensure(
        p.metadata["org.x.nfc"] == json!(nfc) && p.metadata["org.x.nfd"] == json!(nfd),
        "text must not be normalized",
    )
}

pub async fn identifiers(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let pack = ns.root.create_change_pack(PackSpec::default()).await.c()?;
    let upper = pack.to_string().to_uppercase().replacen("CPK_", "cpk_", 1);
    let v = cx.signed_value(
        &ns.root_key,
        ns.root_id,
        Some(ns.id),
        json!({"type": "GetChangePack", "pack": upper}),
        |_| {},
    );
    let got = cx.target.query_value(v).await.c()?;
    ensure(
        got["id"] == json!(pack.to_string()),
        "identifiers must be accepted case-insensitively and emitted lowercase",
    )?;
    for bad in [
        "cpk_short",
        "xyz_agjdus24nvyadaareizuivlgo4",
        "cpk_aaaaaaaaaaaaaaaaaaaaaaaaaa",
    ] {
        let v = cx.signed_value(
            &ns.root_key,
            ns.root_id,
            Some(ns.id),
            json!({"type": "GetChangePack", "pack": bad}),
            |_| {},
        );
        expect_code(cx.target.query_value(v).await, ErrorCode::InvalidArgument)
            .map_err(|e| format!("{bad}: {e}"))?;
    }
    Ok(())
}

pub async fn signatures(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let body = json!({"type": "GetNamespace"});
    // Wrong domain.
    let mut v = cx.signed_value(&ns.root_key, ns.root_id, Some(ns.id), body.clone(), |_| {});
    let mut unsigned = v.clone();
    unsigned
        .as_object_mut()
        .ok_or("object")?
        .remove("signature");
    use openaevc_crypto::Signer;
    let msg = openaevc_canonical::encode(&unsigned).map_err(|e| e.to_string())?;
    v["signature"] = json!(ns
        .root_key
        .sign(openaevc_crypto::Domain::Grant, &msg)
        .to_string());
    expect_code(cx.target.query_value(v).await, ErrorCode::Unauthorized)?;
    // Malformed signature.
    let mut v = cx.signed_value(&ns.root_key, ns.root_id, Some(ns.id), body.clone(), |_| {});
    v["signature"] = json!("AAAA");
    let r = cx.target.query_value(v).await;
    ensure(
        matches!(&r, Err(e) if matches!(e.code, ErrorCode::Unauthorized | ErrorCode::InvalidArgument)),
        format!("malformed signature accepted: {r:?}"),
    )?;
    // Non-canonical S (S + L) of an otherwise valid signature: strict verification refuses it.
    let v = cx.signed_value(&ns.root_key, ns.root_id, Some(ns.id), body.clone(), |_| {});
    let sig: openaevc_protocol::Signature = v["signature"]
        .as_str()
        .ok_or("signature")?
        .parse()
        .map_err(|_| "signature")?;
    let l: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut high = *sig.as_bytes();
    let mut carry = 0u16;
    for i in 0..32 {
        let x = high[32 + i] as u16 + l[i] as u16 + carry;
        high[32 + i] = x as u8;
        carry = x >> 8;
    }
    let mut v = v;
    v["signature"] = json!(openaevc_protocol::b64::encode(&high));
    expect_code(cx.target.query_value(v).await, ErrorCode::Unauthorized)?;
    // A principal registered with a small-order key must never authenticate with the
    // universal forgery (R = identity, S = 0).
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let weak = ns
        .root
        .register_principal(NewPrincipal {
            kind: PrincipalKind::Key,
            public_key: Some(PublicKey::from_bytes(identity)),
            linked_to: None,
            attributes: Default::default(),
        })
        .await;
    if let Ok(weak) = weak {
        let mut forged = [0u8; 64];
        forged[0] = 1;
        let mut v = cx.signed_value(&ns.root_key, weak, Some(ns.id), body.clone(), |_| {});
        v["signature"] = json!(openaevc_protocol::b64::encode(&forged));
        expect_code(cx.target.query_value(v).await, ErrorCode::Unauthorized)?;
    }
    // Another key.
    let other = openaevc_crypto::SigningKey::generate();
    let v = cx.signed_value(&other, ns.root_id, Some(ns.id), body, |_| {});
    expect_code(cx.target.query_value(v).await, ErrorCode::Unauthorized).map(drop)
}

pub async fn errors(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let m = cx.member(&ns).await?;
    let e = expect_code(
        m.client.create_change_pack(PackSpec::default()).await,
        ErrorCode::Forbidden,
    )?;
    ensure(
        e.category == ErrorCategory::Authority && !e.retryable,
        "error category/retryability",
    )?;
    ensure(
        e.missing_action.as_deref() == Some("changepack.create"),
        "missing_action must name the action",
    )?;
    // A failed command leaves no state behind.
    let before = cx.events(&ns.root).await?.len();
    let bogus = openaevc_crypto::sha256(b"conformance-missing");
    expect_code(
        ns.root.create_baseline(vec![bogus], vec![]).await,
        ErrorCode::NotFound,
    )?;
    ensure(
        cx.events(&ns.root).await?.len() == before,
        "failed command must not append events",
    )?;
    // Diagnostics must not leak storage internals or key material.
    let seed_hex: String = ns
        .root_key
        .seed()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let probes = [
        ns.root
            .command(Command::RegisterExtension {
                entrypoint: "missing".into(),
                artifact_digest: bogus,
                approved_host_capabilities: vec![],
            })
            .await
            .err(),
        ns.root.get_object(bogus).await.err(),
        Some(e),
    ];
    for p in probes.into_iter().flatten() {
        let m = p.message.to_lowercase();
        ensure(
            !m.contains("select ")
                && !m.contains("sqlite")
                && !m.contains(&seed_hex)
                && !m.contains("/tmp/"),
            format!("error leaks internals: {}", p.message),
        )?;
    }
    Ok(())
}

pub async fn versioning(cx: &Ctx) -> CaseResult {
    let info = cx.target.info().await.c()?;
    ensure(
        info.protocol.contains(PROTOCOL_VERSION) && info.contract.contains(CONTRACT_VERSION),
        "info must list supported ranges",
    )?;
    ensure(
        SUPPORTED_PROTOCOL.negotiate(&info.protocol) == Some(PROTOCOL_VERSION),
        "negotiation must select the highest common version",
    )?;
    let ns = cx.namespace().await?;
    let v = cx.signed_value(
        &ns.root_key,
        ns.root_id,
        Some(ns.id),
        json!({"type": "GetNamespace"}),
        |v| v["protocol_version"] = json!("9.0.0"),
    );
    expect_code(
        cx.target.query_value(v).await,
        ErrorCode::ProtocolVersionUnsupported,
    )
    .map(drop)
}

pub async fn ordering(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let r = ns.root.create_change_pack(PackSpec::default()).await.c()?;
    ns.root.get_change_pack(r).await.c()?;
    let events = cx.events(&ns.root).await?;
    ensure(
        events
            .windows(2)
            .all(|w| w[1].sequence == w[0].sequence + 1),
        "sequences must be gap-free and increasing",
    )?;
    let receipt = ns
        .root
        .command(Command::CreateChangePack {
            spec: PackSpec::default(),
        })
        .await
        .c()?;
    let obj = ns.root.get_object(receipt.receipt).await.c()?;
    let body: Receipt = obj.body().c()?;
    let text = body.completed_at.to_string();
    ensure(
        text.len() == 30 && text.ends_with('Z'),
        format!("object timestamps must use nine fraction digits: {text}"),
    )
}
