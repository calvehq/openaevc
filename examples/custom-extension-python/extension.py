#!/usr/bin/env python3
"""A custom OpenAEVC domain written in Python: tallies.

Resource `tally.mark`, effect `tally.add {"item": str}` (requires action `tally.write`), verifier
`tally.contains {"item": str}`. The `openaevc` package (sdk/python) must be importable; the
runtime starts extensions with a cleared environment, so place it next to this file.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from openaevc.extension import Extension, ExtensionError, artifact_digest, contract_range, serve, version_range  # noqa: E402

ID = "org.example.tally"


def valid(effect):
    p = effect.get("payload")
    return (
        effect.get("kind") == "tally.add"
        and effect["target"]["kind"] == "tally.mark"
        and effect["target"]["extension"] == ID
        and isinstance(p, dict)
        and set(p) == {"item"}
        and isinstance(p["item"], str)
    )


class Tally(Extension):
    def manifest(self):
        return {
            "id": ID,
            "version": "1.0.0",
            "protocol": version_range(),
            "contract": contract_range(),
            "artifact_digest": artifact_digest(sys.argv[0]),
            "resource_kinds": [{"kind": "tally.mark"}],
            "effect_kinds": [{"kind": "tally.add", "resource_kind": "tally.mark", "required_actions": ["tally.write"]}],
            "verifier_kinds": ["tally.contains"],
            "execution_modes": ["subprocess"],
            "entrypoint": {"command": "extension.py"},
        }

    def handle(self, op, host):
        kind = op["op"]
        if kind == "validate_effect":
            ok = valid(op["effect"])
            return {"valid": True} if ok else {"valid": False, "reason": 'tally.add takes {"item": string}'}
        if kind == "apply_effect":
            return {"outcome": {"added": op["effect"]["payload"]["item"]}}
        if kind == "verify" and op["kind"] == "tally.contains":
            want = op.get("config", {}).get("item")
            items = [e["payload"]["item"] for e in op["effects"] if e["kind"] == "tally.add"]
            return {"status": "PASS" if want in items else "FAIL", "facts": {"tally.count": len(items)}}
        raise ExtensionError("unsupported", kind)


if __name__ == "__main__":
    sys.exit(serve(Tally()))
