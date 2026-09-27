"""Signed sessions and the openaevcd HTTP client (TCP or Unix-domain socket)."""
import datetime
import http.client
import json
import os
import socket

from ._generated import PROTOCOL_VERSION
from .canonical import decode, encode, prune
from .crypto import SigningKey, b64url, sha256
from .ids import new_id


def canonical_timestamp(dt: datetime.datetime) -> str:
    """RFC 3339 UTC with exactly nine fraction digits (the canonical protocol form)."""
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "000Z"


class ProtocolError(Exception):
    """A structured OpenAEVC error (spec/errors.md)."""

    def __init__(self, detail: dict):
        super().__init__(f"{detail.get('code')}: {detail.get('message')}")
        self.detail = detail
        self.code = detail.get("code")
        self.retryable = bool(detail.get("retryable"))


class Session:
    def __init__(self, key: SigningKey, principal: str, namespace: str | None = None, act_as: str | None = None):
        self.key, self.principal, self.namespace, self.act_as = key, principal, namespace, act_as

    def with_namespace(self, ns: str) -> "Session":
        return Session(self.key, self.principal, ns, self.act_as)

    def envelope(self, body: dict) -> dict:
        now = canonical_timestamp(datetime.datetime.now(datetime.timezone.utc))
        env = prune({
            "protocol_version": PROTOCOL_VERSION,
            "request_id": new_id("req"),
            "namespace": self.namespace,
            "caller": self.principal,
            "act_as": self.act_as,
            "nonce": b64url(os.urandom(16)),
            "issued_at": now,
            "body": prune(body),
        })
        env["signature"] = self.key.sign("request", encode(env))
        return env

    def sign_grant(self, body: dict) -> dict:
        b = prune(body)
        return {"body": b, "signature": self.key.sign("grant", encode(b))}


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._path)


class Client:
    """`endpoint` is `"host:port"` or `"unix:/path/to/socket"`."""

    def __init__(self, endpoint: str, session: Session, timeout: float = 60.0):
        self.endpoint, self.session, self.timeout = endpoint, session, timeout

    def with_session(self, session: Session) -> "Client":
        return Client(self.endpoint, session, self.timeout)

    def _conn(self, timeout=None):
        t = self.timeout if timeout is None else timeout
        if self.endpoint.startswith("unix:"):
            return _UnixConnection(self.endpoint[5:], t)
        host, port = self.endpoint.rsplit(":", 1)
        return http.client.HTTPConnection(host, int(port), timeout=t)

    def _request(self, method: str, path: str, headers: dict, body: bytes | None = None):
        conn = self._conn()
        try:
            conn.request(method, path, body=body, headers={"host": "localhost", **headers})
            resp = conn.getresponse()
            data = resp.read()
        except OSError as e:
            raise ProtocolError({"code": "INTERNAL", "message": f"transport: {e}", "retryable": True}) from e
        finally:
            conn.close()
        if not 200 <= resp.status < 300:
            try:
                detail = json.loads(data)
            except ValueError:
                detail = {"code": "INTERNAL", "message": f"HTTP {resp.status}", "retryable": False}
            raise ProtocolError(detail)
        return resp, data

    def _post(self, path: str, env: dict):
        _, data = self._request("POST", path, {"content-type": "application/cbor", "accept": "application/cbor"}, encode(env))
        return decode(data)

    def info(self) -> dict:
        return json.loads(self._request("GET", "/v1/info", {})[1])

    def negotiate(self) -> str:
        info = self.info()
        v = tuple(map(int, PROTOCOL_VERSION.split(".")))
        lo = tuple(map(int, info["protocol"]["min"].split(".")))
        hi = tuple(map(int, info["protocol"]["max"].split(".")))
        if not lo <= v <= hi:
            raise ProtocolError({"code": "PROTOCOL_VERSION_UNSUPPORTED", "message": f"daemon supports {lo}..{hi}", "retryable": False})
        return PROTOCOL_VERSION

    def command(self, body: dict) -> dict:
        return self._post("/v1/commands", self.session.envelope(body))

    def query(self, body: dict):
        return self._post("/v1/queries", self.session.envelope(body))

    def get_object(self, digest: str) -> bytes:
        env = self.session.envelope({"type": "GetObject", "digest": digest})
        _, data = self._request("GET", f"/v1/objects/{digest}", {"openaevc-envelope": b64url(encode(env))})
        if sha256(data) != digest:
            raise ProtocolError({"code": "DIGEST_MISMATCH", "message": "object bytes do not match their digest", "retryable": False})
        return data

    def put_object(self, digest: str, data: bytes) -> dict:
        env = self.session.envelope({"type": "PutImmutableObject", "digest": digest, "bytes": ""})
        headers = {"openaevc-envelope": b64url(encode(env)), "content-type": "application/cbor"}
        return json.loads(self._request("PUT", f"/v1/objects/{digest}", headers, data)[1])

    def events(self, after: int = 0, kinds=(), subjects=(), timeout: float = 30.0):
        """Yields journal events (dicts) from the SSE stream."""
        env = self.session.envelope({"type": "ListEvents", "after": after, "kinds": list(kinds)})
        qs = "&".join(f"subject={s}" for s in subjects)
        conn = self._conn(timeout)
        conn.request("GET", "/v1/events" + (f"?{qs}" if qs else ""), headers={"host": "localhost", "openaevc-envelope": b64url(encode(env)), "accept": "text/event-stream"})
        resp = conn.getresponse()
        if resp.status >= 300:
            raise ProtocolError(json.loads(resp.read() or b"{}"))
        try:
            kind, data = "", ""
            while True:
                line = resp.readline()
                if not line:
                    return
                line = line.decode().rstrip("\r\n")
                if line == "":
                    if data:
                        if kind == "error":
                            raise ProtocolError(json.loads(data))
                        yield json.loads(data)
                    kind, data = "", ""
                elif line.startswith("event:"):
                    kind = line[6:].strip()
                elif line.startswith("data:"):
                    data += line[5:].lstrip()
        finally:
            conn.close()

    # ---- typed helpers ----------------------------------------------------------------

    def create_namespace(self, roots: list) -> tuple:
        r = self.command({"type": "CreateNamespace", "root_principals": roots})
        return r["result"]["id"], r["result"]["ids"]

    def register_principal(self, principal: dict) -> str:
        return self.command({"type": "RegisterPrincipal", "principal": principal})["result"]["id"]

    def register_extension(self, entrypoint: str, digest: str, approved=("resource.read",)) -> str:
        return self.command({"type": "RegisterExtension", "entrypoint": entrypoint, "artifact_digest": digest, "approved_host_capabilities": list(approved)})["result"]["digest"]

    def register_provider(self, provider: dict) -> str:
        return self.command({"type": "RegisterProvider", "provider": provider})["result"]["id"]

    def create_change_pack(self, spec: dict | None = None) -> str:
        return self.command({"type": "CreateChangePack", "spec": spec or {}})["result"]["id"]

    def get_change_pack(self, pack: str) -> dict:
        return self.query({"type": "GetChangePack", "pack": pack})

    def add_work_unit(self, pack: str, generation: int, kind: str) -> str:
        return self.command({"type": "AddWorkUnit", "pack": pack, "expected_generation": generation, "kind": kind})["result"]["id"]

    def start_execution(self, request: dict) -> dict:
        return self.command({"type": "StartExecution", "request": request})["result"]["lease"]

    def heartbeat(self, lease: dict) -> dict:
        return self.command({"type": "HeartbeatExecution", "execution": lease["execution"], "lease": lease["id"], "generation": lease["generation"]})

    def submit_effect(self, lease: dict, effect: dict) -> bool:
        r = self.command({"type": "SubmitEffectProposal", "execution": lease["execution"], "lease": lease["id"], "effect": effect})
        return r["result"].get("state") == "APPLIED"

    def complete_execution(self, lease: dict) -> dict:
        return self.command({"type": "CompleteExecution", "execution": lease["execution"], "lease": lease["id"]})

    def seal(self, pack: str, generation: int) -> str:
        return self.command({"type": "SealChangePack", "pack": pack, "expected_generation": generation})["result"]["digest"]

    def run_verification(self, pack: str, generation: int, verifier: str, config: dict) -> dict:
        return self.command({"type": "RunVerification", "pack": pack, "generation": generation, "verifier": verifier, "config": config})

    def refresh_qualification(self, pack: str, generation: int) -> dict:
        return self.command({"type": "RefreshQualification", "pack": pack, "generation": generation})

    def promote(self, pack: str, generation: int) -> str:
        return self.command({"type": "PromoteChangePack", "pack": pack, "generation": generation})["result"]["digest"]

    def create_baseline(self, members: list, edges: list | None = None) -> tuple:
        r = self.command({"type": "CreateBaseline", "members": members, "edges": edges or []})
        return r["result"]["id"], r["result"]["digest"]
