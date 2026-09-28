# @openaevc/sdk (TypeScript)

Client SDK for OpenAEVC protocol 0.1.0. Runtime dependencies: none (Node ≥ 22.6, `node:crypto`, `node:http`).

```ts
import { Client, Session, SigningKey } from '@openaevc/sdk';

const key = SigningKey.fromHex(process.env.ROOT_SEED!);
const c = new Client({ host: '127.0.0.1', port: 7878 }, new Session(key, principalId, namespaceId));
await c.negotiate();
const pack = await c.createChangePack();
const candidate = await c.seal(pack, 1);
for await (const e of c.events({ kinds: ['changepack.sealed'] })) console.log(e.sequence, e.kind);
```

Unix sockets: `new Client({ socketPath: "/var/lib/openaevc/openaevcd.sock" }, session)`.

- `encode`/`decode` — deterministic CBOR; `sha256`, `digestOf` — protocol digests.
- `SigningKey` — Ed25519 with protocol domain separation; `Session.signGrant` signs grants.
- `generated.ts` — types for every protocol schema definition (regenerate with `cargo run -p generate-sdks`).

Tests: `npm test` (golden fixtures), `npm run typecheck`. `test/e2e.ts` runs the full flow against a daemon (used by Scenario J).
