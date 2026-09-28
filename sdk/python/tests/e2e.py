"""Scenario J (Python): create -> execute -> verify -> promote -> baseline against openaevcd.

Environment: OPENAEVC_ENDPOINT (host:port), OPENAEVC_ADMIN_KEY, OPENAEVC_KV_ENTRYPOINT, OPENAEVC_KV_DIGEST.
"""
import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from openaevc import Client, ProtocolError, Session, SigningKey  # noqa: E402

endpoint = os.environ["OPENAEVC_ENDPOINT"]
admin = json.loads(pathlib.Path(os.environ["OPENAEVC_ADMIN_KEY"]).read_text())
admin_client = Client(endpoint, Session(SigningKey.from_hex(admin["seed"]), admin["id"]))
admin_client.negotiate()
root_key = SigningKey.generate()
ns, roots = admin_client.create_namespace([{"kind": "KEY", "public_key": root_key.public_key}])
c = Client(endpoint, Session(root_key, roots[0], ns))
c.register_extension(os.environ["OPENAEVC_KV_ENTRYPOINT"], os.environ["OPENAEVC_KV_DIGEST"])
c.register_provider({
    "id": "org.example.py-provider", "version": "1.0.0", "worker_kinds": ["org.example.worker"],
    "harnesses": ["org.example.harness"], "cancellation": True, "resumable": False, "heartbeat": True, "principal": roots[0],
})
pack = c.create_change_pack()
wu = c.add_work_unit(pack, 1, "org.example.task")
lease = c.start_execution({
    "pack": pack, "expected_generation": 2, "work_unit": wu, "provider": "org.example.py-provider",
    "harness": "org.example.harness", "allowed_resources": [{"kind": "kv.entry"}], "allowed_effects": ["kv.set"],
    "timeout_ms": 60000, "max_attempts": 1, "idempotency_key": "py-e2e",
})
c.heartbeat(lease)
effect = {"kind": "kv.set", "target": {"kind": "kv.entry", "locator": "lang", "extension": "org.openaevc.reference.kv"}, "payload": {"value": "python"}}
assert c.submit_effect(lease, effect), "effect rejected"
c.complete_execution(lease)
candidate = c.seal(pack, 2)
assert c.run_verification(pack, 2, "kv.expect", {"key": "lang", "value": "python"})["result"]["state"] == "PASS"
assert c.refresh_qualification(pack, 2)["result"]["state"] == "QUALIFIED"
promoted = c.promote(pack, 2)
_, digest = c.create_baseline([promoted])
assert c.query({"type": "ValidateBaseline", "digest": digest})["valid"]
c.get_object(candidate)
for e in c.events(kinds=["changepack.promoted"]):
    assert e["body"]["pack"] == pack
    break
# Digest subjects survive the query string.
for e in c.events(subjects=[promoted]):
    assert promoted in e["subjects"]
    break
# Protocol error codes reach the caller intact.
try:
    c.seal(pack, 2)
    raise AssertionError("sealing a promoted pack succeeded")
except ProtocolError as err:
    assert err.code == "IMMUTABLE_OBJECT", err.code
print(f"python e2e ok {promoted}")
