//! Schema generation shared by `generate-schemas` and `generate-sdks`.
//!
//! Writes `schemas/json/openaevc.schema.json` (JSON Schema 2020-12) and
//! `schemas/cddl/openaevc.cddl` (CDDL for the canonical CBOR data model, which mirrors the
//! JSON data model). With `--check`, fails if the checked-in files differ.

use std::collections::BTreeMap;
use std::path::PathBuf;

use openaevc_protocol as p;
use schemars::generate::SchemaSettings;
use serde_json::{json, Value};

pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

macro_rules! roots {
    ($gen:ident, $($t:ty),* $(,)?) => {{
        $( $gen.subschema_for::<$t>(); )*
    }};
}

pub fn json_schema() -> Value {
    let mut gen = SchemaSettings::draft2020_12().into_generator();
    roots!(
        gen,
        p::ObjectEnvelope,
        p::Blob,
        p::SignedGrant,
        p::Revocation,
        p::PolicyDocument,
        p::PolicyDecision,
        p::ExtensionManifest,
        p::Candidate,
        p::Observation,
        p::Evidence,
        p::VerificationResult,
        p::EvaluationResult,
        p::PromotedPack,
        p::PromotionRecord,
        p::Receipt,
        p::Baseline,
        p::JournalCheckpoint,
        p::CommandEnvelope,
        p::QueryEnvelope,
        p::Command,
        p::Query,
        p::CommandReceipt,
        p::CommandResult,
        p::Event,
        p::EventFilter,
        p::ProtocolError,
        p::RuntimeInfo,
        p::Namespace,
        p::Principal,
        p::ChangePack,
        p::Execution,
        p::ActiveEdge,
        p::ProviderDescriptor,
        p::Facts,
    );
    let mut defs: BTreeMap<String, Value> = gen.take_definitions(true).into_iter().collect();
    defs.values_mut().for_each(strip_null);
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://openaevc.org/schemas/0.1.0/openaevc.schema.json",
        "title": "OpenAEVC protocol 0.1.0",
        "description": "JSON representation of OpenAEVC protocol types. Canonical CBOR uses the same data model (spec/canonical-encoding.md).",
        "$defs": defs,
    })
}

/// Absent optional values are omitted, never `null` (AEVC-ENC-0001, AEVC-ENC-0003): removes the
/// `null` alternatives schemars adds for `Option<T>`.
fn strip_null(v: &mut Value) {
    match v {
        Value::Object(m) => {
            if let Some(Value::Array(types)) = m.get_mut("type") {
                types.retain(|t| t != "null");
                if types.len() == 1 {
                    let only = types.remove(0);
                    m.insert("type".into(), only);
                }
            }
            for key in ["anyOf", "oneOf"] {
                if let Some(Value::Array(alts)) = m.get_mut(key) {
                    alts.retain(|a| a != &json!({"type": "null"}));
                    if alts.len() == 1 {
                        let only = alts.remove(0);
                        m.remove(key);
                        if let Value::Object(o) = only {
                            for (k, val) in o {
                                m.entry(k).or_insert(val);
                            }
                        }
                    }
                }
            }
            m.values_mut().for_each(strip_null);
        }
        Value::Array(a) => a.iter_mut().for_each(strip_null),
        _ => {}
    }
}

fn cddl_type(v: &Value) -> String {
    if let Some(r) = v.get("$ref").and_then(Value::as_str) {
        return r
            .rsplit('/')
            .next()
            .unwrap_or("any")
            .replace(['<', '>', ','], "_")
            .to_lowercase();
    }
    for key in ["oneOf", "anyOf"] {
        if let Some(alts) = v.get(key).and_then(Value::as_array) {
            let parts: Vec<String> = alts
                .iter()
                .filter(|a| a.get("type").and_then(Value::as_str) != Some("null"))
                .map(cddl_type)
                .collect();
            return if parts.len() == 1 {
                parts[0].clone()
            } else {
                format!("({})", parts.join(" / "))
            };
        }
    }
    if let Some(c) = v.get("const") {
        return c.to_string();
    }
    if let Some(e) = v.get("enum").and_then(Value::as_array) {
        return format!(
            "({})",
            e.iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(" / ")
        );
    }
    let ty = match v.get("type") {
        Some(Value::Array(ts)) => ts
            .iter()
            .find(|t| *t != "null")
            .and_then(Value::as_str)
            .unwrap_or("any"),
        Some(Value::String(t)) => t.as_str(),
        _ => "any",
    };
    match ty {
        "string" => match v.get("pattern").and_then(Value::as_str) {
            Some(p) => format!("tstr .regexp \"{}\"", p.replace('\\', "\\\\")),
            None => "tstr".into(),
        },
        "integer" => {
            if v.get("minimum").and_then(Value::as_i64) == Some(0) {
                "uint".into()
            } else {
                "int".into()
            }
        }
        "boolean" => "bool".into(),
        "array" => {
            let item = v
                .get("items")
                .map(cddl_type)
                .unwrap_or_else(|| "any".into());
            format!("[* {item}]")
        }
        "object" => cddl_object(v),
        _ => "any".into(),
    }
}

fn cddl_object(v: &Value) -> String {
    let props = v.get("properties").and_then(Value::as_object);
    let required: Vec<&str> = v
        .get("required")
        .and_then(Value::as_array)
        .map(|r| r.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let mut fields = Vec::new();
    if let Some(props) = props {
        for (k, pv) in props {
            let opt = if required.contains(&k.as_str()) {
                ""
            } else {
                "? "
            };
            fields.push(format!("{opt}\"{k}\": {}", cddl_type(pv)));
        }
    }
    match v.get("additionalProperties") {
        Some(ap @ Value::Object(_)) => fields.push(format!("* tstr => {}", cddl_type(ap))),
        Some(Value::Bool(false)) => {}
        _ if props.is_none() => fields.push("* tstr => any".into()),
        _ => {}
    }
    format!("{{ {} }}", fields.join(", "))
}

pub fn cddl(schema: &Value) -> String {
    let mut out = String::from(
        "; OpenAEVC protocol 0.1.0 — CDDL for canonical CBOR (RFC 8610).\n\
         ; Generated by tooling/generate-schemas from the protocol types; do not edit.\n\
         ; The canonical data model mirrors JSON: text keys, no floats, no null,\n\
         ; integers within +/-(2^53-1), binary values as unpadded base64url text.\n\n",
    );
    for (name, def) in schema["$defs"].as_object().into_iter().flatten() {
        let rule = name.replace(['<', '>', ','], "_").to_lowercase();
        out.push_str(&format!("{rule} = {}\n", cddl_type(def)));
    }
    out
}
