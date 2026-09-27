//! OpenAPI 3.1 description of the v1 daemon transport. Protocol schemas are referenced from the
//! checked-in JSON Schema (`schemas/json/openaevc.schema.json`).

use serde_json::{json, Value};

const SCHEMA: &str = "https://openaevc.org/schemas/0.1.0/openaevc.schema.json#/$defs/";

fn r(name: &str) -> Value {
    json!({"$ref": format!("{SCHEMA}{name}")})
}

fn body(name: &str) -> Value {
    json!({"required": true, "content": {
        "application/json": {"schema": r(name)},
        "application/cbor": {"schema": r(name)}
    }})
}

fn ok(name: &str) -> Value {
    json!({"description": "Success", "content": {
        "application/json": {"schema": r(name)},
        "application/cbor": {"schema": r(name)}
    }})
}

fn errors() -> Value {
    let e = json!({"description": "Structured protocol error", "content": {"application/json": {"schema": r("ProtocolError")}}});
    json!({"400": e, "401": e, "403": e, "404": e, "409": e, "422": e, "500": e, "502": e, "503": e})
}

fn with_errors(ok_responses: Value) -> Value {
    let mut m = errors();
    if let (Some(dst), Some(src)) = (m.as_object_mut(), ok_responses.as_object()) {
        for (k, v) in src {
            dst.insert(k.clone(), v.clone());
        }
    }
    m
}

pub fn document() -> Value {
    let envelope_header = json!({"name": "openaevc-envelope", "in": "header", "required": true,
        "description": "Unpadded base64url of the canonical CBOR of a signed envelope",
        "schema": {"type": "string"}});
    let digest = json!({"name": "digest", "in": "path", "required": true, "schema": r("Digest")});
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "OpenAEVC daemon transport",
            "version": "0.1.0",
            "description": "One authoritative semantic surface: signed command/query envelopes, object exchange and journal events. Authorization is decided by the runtime for every request.",
            "license": {"name": "Apache-2.0", "identifier": "Apache-2.0"}
        },
        "paths": {
            "/v1/info": {"get": {"operationId": "getInfo", "summary": "Runtime and supported protocol/contract ranges (unauthenticated)",
                "responses": {"200": ok("RuntimeInfo")}}},
            "/v1/commands": {"post": {"operationId": "executeCommand", "requestBody": body("CommandEnvelope"),
                "responses": with_errors(json!({"200": ok("CommandReceipt")}))}},
            "/v1/queries": {"post": {"operationId": "executeQuery", "requestBody": body("QueryEnvelope"),
                "responses": with_errors(json!({"200": {"description": "Query result (shape depends on the query)", "content": {"application/json": {}}}}))}},
            "/v1/events": {"get": {"operationId": "streamEvents",
                "summary": "Server-sent journal events for a signed ListEvents envelope; resume with Last-Event-ID",
                "parameters": [envelope_header, {"name": "subject", "in": "query", "schema": {"type": "array", "items": {"type": "string"}}},
                    {"name": "Last-Event-ID", "in": "header", "schema": {"type": "string"}}],
                "responses": with_errors(json!({"200": {"description": "text/event-stream of Event JSON", "content": {"text/event-stream": {"schema": r("Event")}}}}))}},
            "/v1/objects/{digest}": {
                "get": {"operationId": "getObject", "parameters": [digest.clone(), envelope_header.clone()],
                    "responses": with_errors(json!({"200": {"description": "Canonical CBOR bytes", "content": {"application/cbor": {}}}}))},
                "put": {"operationId": "putObject", "parameters": [digest, envelope_header],
                    "requestBody": {"required": true, "content": {"application/cbor": {}}},
                    "responses": with_errors(json!({"200": ok("CommandReceipt")}))}
            },
            "/v1/openapi.json": {"get": {"operationId": "getOpenApi", "responses": {"200": {"description": "This document"}}}},
            "/v1/health/live": {"get": {"operationId": "live", "responses": {"200": {"description": "Process is alive"}}}},
            "/v1/health/ready": {"get": {"operationId": "ready", "responses": {"200": {"description": "Ready"}, "503": {"description": "Not ready"}}}},
            "/v1/metrics": {"get": {"operationId": "metrics", "responses": {"200": {"description": "Prometheus text exposition", "content": {"text/plain": {}}}}}}
        }
    })
}
