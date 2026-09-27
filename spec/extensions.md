# Extension Contract

Contract version **0.1.0**, versioned independently of the protocol. Extensions implement domains (resource kinds, effect kinds, verifiers, evaluators, composition validators) without changes to the core. The runtime decides whether effects may be proposed, validated, applied, recorded and accepted; extensions only interpret.

## Identity and manifest

An extension is identified by a reverse-DNS ID (`org.openaevc.reference.kv`) and a SemVer version. Its `ExtensionManifest` declares: supported protocol and contract ranges, optional publisher key, `artifact_digest` (SHA-256 of the executable), resource kinds, effect kinds (each with its target resource kind and the authority `required_actions`), verifier kinds, evaluator kinds, composition validators, requested host capabilities, schema digests, execution modes and entrypoint.

## Registration

`RegisterExtension{entrypoint, artifact_digest, approved_host_capabilities}` (action `extension.register`):

**AEVC-EXT-0001** The entrypoint MUST be a plain relative path resolved inside a runtime-configured extension directory (no absolute paths, `..` or symlink escapes: `INVALID_ARGUMENT`). Being present on the machine never makes an extension trusted.

**AEVC-EXT-0002** The runtime MUST verify that SHA-256 of the executable equals the caller-pinned `artifact_digest` and the manifest's `artifact_digest`, and that the protocol and contract ranges intersect the runtime's, before registering; otherwise `EXTENSION_INCOMPATIBLE` and nothing is recorded.

**AEVC-EXT-0003** A kind may be provided by at most one active extension per Namespace (`CONFLICT`). Re-registering the same extension ID replaces its active registration (upgrade); earlier manifests remain immutable objects so promoted history stays resolvable.

**AEVC-EXT-0004** Successful registration stores the manifest as an immutable `extension_manifest` object and appends an `extension.registered` event naming the granted host capabilities: the intersection of manifest requests and caller approvals.

## Wire protocol (subprocess mode)

Frames are a 4-byte big-endian length followed by canonical CBOR of one message. Host → extension: `hello{protocol, contract}`, `invoke{id, deadline_ms, granted, operation}`, `host_result{invocation, call, ok | error}`, `cancel{id}`, `shutdown{}`. Extension → host: `hello{manifest, protocol, contract}`, `host_call{invocation, call, request}`, `result{id, output}`, `error{id, error{code, message}}`.

Operations: `validate_effect{effect, prior}`, `apply_effect{effect, prior}`, `verify{kind, config?, pack, generation, candidate, effects, evidence}`, `evaluate{kind, config?, facts, effects}`, `compose{validator, config?, members, edges}`. `prior` is the list of effects already applied to the same resource in the candidate.

Host calls and the capability each requires: `resource.read` (resource.read), `process.execute` (process.execute), `clock.now` (clock.read), `entropy.random` (entropy.read), and uncapped `evidence.attach`, `fact.emit`, `config.resolve`, `log`.

**AEVC-EXT-0005** Each invocation is granted only capabilities that the manifest requested, the registration approved, and the operation allows (`validate_effect`/`evaluate`: resource.read, clock.read; `apply_effect`: all; `verify`: all but resource.write; `compose`: none). A host call needing an ungranted capability, or reading a resource outside the invocation's scope, MUST terminate the invocation and fail closed (`EXTENSION_FAILED`).

**AEVC-EXT-0006** The host MUST enforce a deadline for the whole exchange, a maximum frame size and a host-call budget; malformed frames, oversized frames, unexpected messages, crashes and deadline overruns fail the invocation with `EXTENSION_FAILED` and the process is killed. The runtime remains available.

**AEVC-EXT-0007** Extensions MUST NOT receive storage paths, database handles or runtime credentials: the reference host starts each invocation in a fresh process with a cleared environment (only `PATH`) and the extension directory as working directory. Extensions change runtime state only through outputs the runtime validates and records.

**AEVC-EXT-0008** The runtime MUST re-verify the executable's digest before every invocation; a changed artifact fails with `EXTENSION_INCOMPATIBLE`.

The reference host does not sandbox the operating-system process; `network.connect` and `secret.read` are grantable declarations without reference host calls. Deployments requiring OS-level isolation run extensions under their own sandbox.

## Reference extensions

- `reference-null` (`org.openaevc.reference.null`): `null.item`, effect `null.noop`, verifier `null.pass` with deterministic evidence.
- `reference-kv` (`org.openaevc.reference.kv`): `kv.entry`, effects `kv.set`/`kv.delete` with preconditions, verifier `kv.expect`, evaluator `kv.size`, composition validator `kv.terminal-values`. It proves a non-software domain works without core changes.
- `conformance-fixtures`: deliberately misbehaving modes for conformance tests.
