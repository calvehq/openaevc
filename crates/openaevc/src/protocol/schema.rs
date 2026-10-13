//! JSON Schema descriptions for protocol types with a custom text form.

use std::borrow::Cow;

use schemars::{json_schema, JsonSchema, Schema, SchemaGenerator};

macro_rules! string_schema {
    ($t:ty, $name:literal, $pattern:expr, $desc:literal) => {
        impl JsonSchema for $t {
            fn schema_name() -> Cow<'static, str> {
                $name.into()
            }

            fn json_schema(_: &mut SchemaGenerator) -> Schema {
                json_schema!({ "type": "string", "pattern": $pattern, "description": $desc })
            }
        }
    };
}

string_schema!(
    crate::protocol::Digest,
    "Digest",
    "^sha256:[0-9a-f]{64}$",
    "Algorithm-tagged SHA-256 digest."
);
string_schema!(
    crate::protocol::Timestamp,
    "Timestamp",
    "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,9})?Z$",
    "RFC 3339 UTC timestamp; canonical output has nine fraction digits."
);
string_schema!(
    crate::protocol::ProtocolVersion,
    "ProtocolVersion",
    "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$",
    "MAJOR.MINOR.PATCH protocol version."
);
string_schema!(
    crate::protocol::PublicKey,
    "PublicKey",
    "^ed25519:[A-Za-z0-9_-]{43}$",
    "Ed25519 public key, unpadded base64url."
);
string_schema!(
    crate::protocol::Signature,
    "Signature",
    "^[A-Za-z0-9_-]{86}$",
    "Ed25519 signature, unpadded base64url."
);
string_schema!(
    crate::protocol::PackId,
    "PackId",
    "^(cpk|rpk)_[a-z2-7]{26}$",
    "ChangePack or RevisionPack identifier."
);
string_schema!(
    crate::protocol::NodeRef,
    "NodeRef",
    "^([a-z]{2,3}_[a-z2-7]{26}|sha256:[0-9a-f]{64})$",
    "Active Change Graph node: typed identifier or object digest."
);
string_schema!(
    crate::protocol::AnyId,
    "AnyId",
    "^[a-z]{2,3}_[a-z2-7]{26}$",
    "Any typed identifier."
);
