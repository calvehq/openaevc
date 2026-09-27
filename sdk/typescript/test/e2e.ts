// Scenario J (TypeScript): create -> execute -> verify -> promote -> baseline against openaevcd.
// Environment: OPENAEVC_ENDPOINT (host:port), OPENAEVC_ADMIN_KEY (JSON {id, seed}),
// OPENAEVC_KV_ENTRYPOINT, OPENAEVC_KV_DIGEST.
import { readFileSync } from "node:fs";
import { Client, Session, SigningKey } from "../src/index.ts";

const [host, port] = process.env.OPENAEVC_ENDPOINT!.split(":");
const admin = JSON.parse(readFileSync(process.env.OPENAEVC_ADMIN_KEY!, "utf8"));
const endpoint = { host, port: Number(port) };
const adminClient = new Client(endpoint, new Session(SigningKey.fromHex(admin.seed), admin.id));
await adminClient.negotiate();

const rootKey = SigningKey.generate();
const { namespace, roots } = await adminClient.createNamespace([{ kind: "KEY", public_key: rootKey.publicKey }]);
const c = new Client(endpoint, new Session(rootKey, roots[0], namespace));
await c.registerExtension(process.env.OPENAEVC_KV_ENTRYPOINT!, process.env.OPENAEVC_KV_DIGEST!, ["resource.read"]);
await c.registerProvider({
  id: "org.example.ts-provider", version: "1.0.0", worker_kinds: ["org.example.worker"], harnesses: ["org.example.harness"],
  cancellation: true, resumable: false, heartbeat: true, principal: roots[0],
});
const pack = await c.createChangePack();
const wu = await c.addWorkUnit(pack, 1, "org.example.task");
const { lease } = await c.startExecution({
  pack, expected_generation: 2, work_unit: wu, provider: "org.example.ts-provider", harness: "org.example.harness",
  allowed_resources: [{ kind: "kv.entry" }], allowed_effects: ["kv.set"], timeout_ms: 60000, max_attempts: 1, idempotency_key: "ts-e2e",
});
await c.heartbeat(lease);
const effect = { kind: "kv.set", target: { kind: "kv.entry", locator: "lang", extension: "org.openaevc.reference.kv" }, payload: { value: "typescript" } };
if (!(await c.submitEffect(lease, effect))) throw new Error("effect rejected");
await c.completeExecution(lease);
const candidate = await c.seal(pack, 2);
const v = await c.runVerification(pack, 2, "kv.expect", { key: "lang", value: "typescript" });
if (v.result.state !== "PASS") throw new Error("verification failed");
const q = await c.refreshQualification(pack, 2);
if (q.result.state !== "QUALIFIED") throw new Error("not qualified");
const promoted = await c.promote(pack, 2);
const { digest } = await c.createBaseline([promoted]);
const valid = await c.query({ type: "ValidateBaseline", digest });
if (!valid.valid) throw new Error("baseline invalid");
await c.getObject(candidate);
let seen = 0;
for await (const e of c.events({ kinds: ["changepack.promoted"] })) {
  if (e.body.pack === pack) seen++;
  break;
}
if (seen !== 1) throw new Error("promotion event not observed");
console.log(`typescript e2e ok ${promoted}`);
