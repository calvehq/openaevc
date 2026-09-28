# Conformance

An implementation conforms to a profile of OpenAEVC 0.1.0 when it passes every case of that
profile in the conformance suite (`openaevc-conformance`, version 0.1.0). The suite exercises
implementations only through the protocol surface: signed envelopes, the v1 transport, canonical
objects and the extension contract. It never reads implementation internals.

## Profiles

| Profile          | Covers                                                                                           |
| ---------------- | ------------------------------------------------------------------------------------------------ |
| `CORE`           | Canonical encoding, identifiers, digests, signatures, errors, versioning, object validity         |
| `AUTHORITY`      | Authentication, default deny, capability grants, delegation, revocation, replay, Namespaces       |
| `RUNTIME`        | ChangePack lifecycle, Active Change Graph, execution, evidence, verification, evaluation, policy, promotion, revisions, Baselines, composition, events, transport |
| `EXTENSION_HOST` | Extension registration, pinning, confinement, capabilities, limits, environment, re-verification  |
| `FULL`           | Every profile above, plus restart recovery and object exchange                                    |

Every case cites the requirement IDs it verifies. Every requirement whose text contains MUST or
MUST NOT is cited by at least one case; `tooling/release-check/coverage.py` fails the build
otherwise. Cases include negative checks: each prohibited behaviour named in a requirement is
attempted and the exact error code is asserted.

A case that cannot run against a target (for example, no local extension directory was given)
is reported as `SKIPPED`. A case whose target cannot be driven through it (a restart of a remote
target without a lifecycle controller) is reported as `NOT_EXERCISED`. Neither ever counts as
passed, for any profile: a run is conformant only when every case of the profile passed, and a
requirement is reported as passed only when every case citing it passed.

## Targets

- **In-process**: the Rust reference runtime inside the runner (SQLite store in a temporary data
  root, checkpoint interval 10, extension deadline 10 s, frame limit 1 MiB).
- **Remote**: any implementation serving the v1 transport (`transport.md`). The runner needs an
  admin key for the target (to create Namespaces), and for `EXTENSION_HOST` the local path of
  the target's extension directory, into which the conformance fixture executables are installed.
  Restart and tampering checks of `full.recovery` need control of the implementation's process
  and data root. The runner gets it through a *lifecycle controller*: test infrastructure, not a
  protocol API, that can stop the target abruptly, start it again on the same data root and
  endpoint, and expose that data root. With `--daemon <openaevcd> --daemon-config <toml>
  --daemon-data-root <dir>` the runner launches and owns the reference daemon itself; the case
  then crashes and restarts it, checks that Namespace state, immutable objects, the journal and
  Baselines survive, that a lease which expired while it was down is `LOST` and its late effects
  are refused, that no half-promoted state appears, and that a data root missing committed bytes
  fails closed and is not repaired. Without a controller the restart checks are
  `NOT_EXERCISED` (so the target cannot claim `FULL`), and so are the deadline and frame-size
  checks of `extension.limits`, which need the target's limits configured below the fixtures'.
  The reference daemon's release candidate runs `FULL` this way (Scenario K).
- **Extension**: an extension executable. The runner performs the handshake, checks that the
  manifest pins the executable's digest and a v1 contract range, that declared identifiers are
  namespaced, and that an operation for an undeclared kind is answered with an extension error
  rather than output, a crash or a protocol violation.

## Fixture extensions

`extensions/conformance-fixtures` builds one executable whose behaviour is selected by its file
name, `conformance-fixture-<mode>`: `well-behaved`, `undeclared-resource`, `undeclared-process`,
`oversized`, `invalid-frame`, `wrong-digest`, `slow`, `incompatible`, `crash`, `probe`,
`detached-child`, `no-read`, `wants-unsupported`, `kind-thief`, `upgrade`
(`scripts/install-conformance-extensions.sh` installs them). The
extension directory used for `EXTENSION_HOST` and `RUNTIME` contains these plus
`openaevc-ext-reference-kv` and `openaevc-ext-reference-null`.

## Reports

The runner prints a summary and can write a JSON report (`--report-json`) and JUnit XML
(`--junit`). Reports record the conformance and protocol versions, the profile, the target, the
implementation's `RuntimeInfo`, per-case status and duration, and the passed, failed and skipped
requirement IDs, and the not-exercised ones. The process exits 0 only for a conformant run.

```text
openaevc-conformance --profile FULL --target in-process --extensions <dir>
openaevc-conformance --profile FULL --target remote --endpoint 127.0.0.1:7340 \
    --admin-key admin.json --extensions <daemon extension dir> --checkpoint-interval 1000
openaevc-conformance --profile FULL --target remote --daemon ./openaevcd \
    --daemon-config openaevcd.toml --daemon-data-root ./data \
    --admin-key admin.json --extensions <dir> --checkpoint-interval 10
openaevc-conformance --target extension --extension ./my-extension
```

## Sensitivity

The suite is itself tested against deliberately broken servers, each injecting one semantic
violation into otherwise correct responses: denials rewritten into successes, object bytes
altered in transit, and fake successes for stale generations, promoted-pack mutation, stale
evidence, extension-kind conflicts, unknown signed-object fields, digest mismatches, bad
signatures and replays; `ValidateBaseline` claiming validity; altered event hashes. Each must
fail a case citing the violated requirement (`crates/openaevc-conformance/tests/remote.rs`). The
reference runtime passes `FULL` in-process and, through the daemon, remotely with restarts.
