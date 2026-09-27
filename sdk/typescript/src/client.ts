// Signed sessions and the daemon HTTP client.
import http from "node:http";
import { encode, decode, prune, type Json } from "./canonical.ts";
import { SigningKey, b64url, sha256 } from "./crypto.ts";
import { newId } from "./ids.ts";
import { PROTOCOL_VERSION } from "./generated.ts";
import { randomBytes } from "node:crypto";

/** RFC 3339 UTC with exactly nine fraction digits (the canonical protocol form). */
export function canonicalTimestamp(d: Date): string {
  return d.toISOString().replace(/\.(\d{3})Z$/, ".$1000000Z");
}

export class ProtocolError extends Error {
  readonly code: string;
  readonly retryable: boolean;
  readonly detail: Record<string, unknown>;

  constructor(detail: Record<string, unknown>) {
    super(`${detail.code}: ${detail.message}`);
    this.code = String(detail.code);
    this.retryable = Boolean(detail.retryable);
    this.detail = detail;
  }
}

/** Identity, namespace and signing key for requests. */
export class Session {
  readonly key: SigningKey;
  readonly principal: string;
  readonly namespace?: string;
  readonly actAs?: string;

  constructor(key: SigningKey, principal: string, namespace?: string, actAs?: string) {
    this.key = key;
    this.principal = principal;
    this.namespace = namespace;
    this.actAs = actAs;
  }

  withNamespace(ns: string): Session {
    return new Session(this.key, this.principal, ns, this.actAs);
  }

  /** Builds and signs a canonical request envelope for `body`. */
  envelope(body: Json): Json {
    const env = prune({
      protocol_version: PROTOCOL_VERSION,
      request_id: newId("req"),
      namespace: this.namespace,
      caller: this.principal,
      act_as: this.actAs,
      nonce: b64url(new Uint8Array(randomBytes(16))),
      issued_at: canonicalTimestamp(new Date()),
      body: prune(body),
    }) as { [k: string]: Json };
    env.signature = this.key.sign("request", encode(env));
    return env;
  }

  /** Signs a capability grant body issued by this principal. */
  signGrant(body: Json): Json {
    const b = prune(body);
    return { body: b, signature: this.key.sign("grant", encode(b)) };
  }
}

export type Endpoint = { host: string; port: number } | { socketPath: string };

interface RawResponse {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
}

export class Client {
  readonly endpoint: Endpoint;
  readonly session: Session;

  constructor(endpoint: Endpoint, session: Session) {
    this.endpoint = endpoint;
    this.session = session;
  }

  withSession(session: Session): Client {
    return new Client(this.endpoint, session);
  }

  #request(method: string, path: string, headers: Record<string, string>, body?: Uint8Array): Promise<RawResponse> {
    return new Promise((resolve, reject) => {
      const req = http.request({ ...this.endpoint, method, path, headers: { host: "localhost", ...headers } }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks) }));
        res.on("error", reject);
      });
      req.on("error", (e) => reject(new ProtocolError({ code: "INTERNAL", message: `transport: ${e.message}`, retryable: true })));
      if (body) req.write(body);
      req.end();
    });
  }

  static #check(r: RawResponse): RawResponse {
    if (r.status >= 200 && r.status < 300) return r;
    let detail: Record<string, unknown>;
    try {
      const cbor = String(r.headers["content-type"] ?? "").startsWith("application/cbor");
      detail = (cbor ? decode(new Uint8Array(r.body)) : JSON.parse(r.body.toString("utf8"))) as Record<string, unknown>;
    } catch {
      detail = { code: r.status === 413 ? "INVALID_ARGUMENT" : "INTERNAL", message: `HTTP ${r.status}`, retryable: false };
    }
    throw new ProtocolError(detail);
  }

  async #post(path: string, env: Json): Promise<Json> {
    const r = Client.#check(await this.#request("POST", path, { "content-type": "application/cbor", accept: "application/cbor" }, encode(env)));
    return decode(new Uint8Array(r.body));
  }

  async info(): Promise<{ protocol: { min: string; max: string }; [k: string]: Json }> {
    const r = Client.#check(await this.#request("GET", "/v1/info", {}));
    return JSON.parse(r.body.toString("utf8"));
  }

  /** Reads `/v1/info` and checks that the daemon supports this SDK's protocol version. */
  async negotiate(): Promise<string> {
    const info = await this.info();
    const cmp = (a: string, b: string) => {
      const [x, y] = [a.split(".").map(Number), b.split(".").map(Number)];
      for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] - y[i];
      return 0;
    };
    if (cmp(PROTOCOL_VERSION, info.protocol.min) < 0 || cmp(PROTOCOL_VERSION, info.protocol.max) > 0)
      throw new ProtocolError({ code: "PROTOCOL_VERSION_UNSUPPORTED", message: `daemon supports ${info.protocol.min}..${info.protocol.max}`, retryable: false });
    return PROTOCOL_VERSION;
  }

  command(body: Json): Promise<any> {
    return this.#post("/v1/commands", this.session.envelope(body));
  }

  query(body: Json): Promise<any> {
    return this.#post("/v1/queries", this.session.envelope(body));
  }

  /** Fetches an object and verifies its digest; returns the canonical bytes. */
  async getObject(digest: string): Promise<Uint8Array> {
    const env = this.session.envelope({ type: "GetObject", digest });
    const r = Client.#check(await this.#request("GET", `/v1/objects/${digest}`, { "openaevc-envelope": b64url(encode(env)) }));
    const bytes = new Uint8Array(r.body);
    if (sha256(bytes) !== digest) throw new ProtocolError({ code: "DIGEST_MISMATCH", message: "object bytes do not match their digest", retryable: false });
    return bytes;
  }

  async putObject(digest: string, bytes: Uint8Array): Promise<any> {
    const env = this.session.envelope({ type: "PutImmutableObject", digest, bytes: "" });
    const r = Client.#check(await this.#request("PUT", `/v1/objects/${digest}`, { "openaevc-envelope": b64url(encode(env)), "content-type": "application/cbor" }, bytes));
    return JSON.parse(r.body.toString("utf8"));
  }

  /** Server-sent journal events (at-least-once, in order). */
  async *events(filter: { after?: number; kinds?: string[]; subjects?: string[] } = {}): AsyncGenerator<any> {
    const env = this.session.envelope({ type: "ListEvents", after: filter.after ?? 0, kinds: filter.kinds ?? [] });
    const qs = (filter.subjects ?? []).map((s) => `subject=${encodeURIComponent(s)}`).join("&");
    const res: http.IncomingMessage = await new Promise((resolve, reject) => {
      const req = http.request({ ...this.endpoint, method: "GET", path: `/v1/events${qs ? "?" + qs : ""}`, headers: { host: "localhost", "openaevc-envelope": b64url(encode(env)), accept: "text/event-stream" } }, resolve);
      req.on("error", reject);
      req.end();
    });
    if ((res.statusCode ?? 500) >= 300) {
      const chunks: Buffer[] = [];
      for await (const c of res) chunks.push(c as Buffer);
      Client.#check({ status: res.statusCode ?? 500, headers: res.headers, body: Buffer.concat(chunks) });
    }
    let buf = "";
    try {
      for await (const chunk of res) {
        buf += (chunk as Buffer).toString("utf8");
        let idx: number;
        while ((idx = buf.indexOf("\n\n")) >= 0) {
          const block = buf.slice(0, idx);
          buf = buf.slice(idx + 2);
          let kind = "";
          let data = "";
          for (const line of block.split("\n")) {
            if (line.startsWith("event:")) kind = line.slice(6).trim();
            else if (line.startsWith("data:")) data += line.slice(5).trimStart();
          }
          if (!data) continue;
          if (kind === "error") throw new ProtocolError(JSON.parse(data));
          yield JSON.parse(data);
        }
      }
    } finally {
      res.destroy();
    }
  }

  // ---- typed helpers -------------------------------------------------------------------

  async createNamespace(roots: Json[]): Promise<{ namespace: string; roots: string[] }> {
    const r = await this.command({ type: "CreateNamespace", root_principals: roots });
    return { namespace: r.result.id, roots: r.result.ids };
  }

  async registerPrincipal(p: Json): Promise<string> {
    return (await this.command({ type: "RegisterPrincipal", principal: p })).result.id;
  }

  async createChangePack(spec: Json = {}): Promise<string> {
    return (await this.command({ type: "CreateChangePack", spec })).result.id;
  }

  getChangePack(pack: string): Promise<any> {
    return this.query({ type: "GetChangePack", pack });
  }

  async addWorkUnit(pack: string, expected_generation: number, kind: string): Promise<string> {
    return (await this.command({ type: "AddWorkUnit", pack, expected_generation, kind })).result.id;
  }

  async registerProvider(provider: Json): Promise<string> {
    return (await this.command({ type: "RegisterProvider", provider })).result.id;
  }

  async registerExtension(entrypoint: string, artifact_digest: string, approved: string[]): Promise<string> {
    return (await this.command({ type: "RegisterExtension", entrypoint, artifact_digest, approved_host_capabilities: approved })).result.digest;
  }

  async startExecution(request: Json): Promise<{ execution: string; lease: any }> {
    const r = await this.command({ type: "StartExecution", request });
    return { execution: r.result.id, lease: r.result.lease };
  }

  heartbeat(lease: any): Promise<any> {
    return this.command({ type: "HeartbeatExecution", execution: lease.execution, lease: lease.id, generation: lease.generation });
  }

  async submitEffect(lease: any, effect: Json): Promise<boolean> {
    return (await this.command({ type: "SubmitEffectProposal", execution: lease.execution, lease: lease.id, effect })).result.state === "APPLIED";
  }

  completeExecution(lease: any): Promise<any> {
    return this.command({ type: "CompleteExecution", execution: lease.execution, lease: lease.id });
  }

  async seal(pack: string, expected_generation: number): Promise<string> {
    return (await this.command({ type: "SealChangePack", pack, expected_generation })).result.digest;
  }

  runVerification(pack: string, generation: number, verifier: string, config: Json): Promise<any> {
    return this.command({ type: "RunVerification", pack, generation, verifier, config });
  }

  refreshQualification(pack: string, generation: number): Promise<any> {
    return this.command({ type: "RefreshQualification", pack, generation });
  }

  async promote(pack: string, generation: number): Promise<string> {
    return (await this.command({ type: "PromoteChangePack", pack, generation })).result.digest;
  }

  async createBaseline(members: string[], edges: Json[] = []): Promise<{ baseline: string; digest: string }> {
    const r = await this.command({ type: "CreateBaseline", members, edges });
    return { baseline: r.result.id, digest: r.result.digest };
  }
}
