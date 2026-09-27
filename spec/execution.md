# Execution

Roles: the **runtime** owns lifecycle, authority, provenance and candidate state; a **provider** supplies workers; a **worker** is the process, service, agent or human-operated tool doing the work; a **harness** coordinates the worker through structured commands; **extensions** interpret resources and effects. Workers never mutate accepted state.

## Providers

`RegisterProvider` (action `provider.register`) records a provider descriptor: ID, version, worker kinds, harnesses, required actions, cancellation/resumability/heartbeat support, resource limits, provenance fields, and the principal that speaks for the provider.

## Admission

`StartExecution{request}` (action `execution.start`). The request names pack and expected generation, work unit, provider, harness, optional worker, allowed resource selectors, allowed effect kinds, context object digests, timeout, budget, `max_attempts`, an idempotency key and optionally `retry_of`.

**AEVC-EXE-0001** Before an execution starts the runtime MUST validate, in order: the pack is `OPEN` (otherwise `INVALID_TRANSITION`, `QUARANTINED` or `IMMUTABLE_OBJECT`); the generation matches (`STALE_GENERATION`); the work unit exists and is `OPEN`; every dependency is satisfied (`EXECUTION_NOT_READY`, listing the waiting nodes); the provider is registered and supports the harness and worker kind; every allowed effect kind is provided by an active extension bound to the pack (`EXTENSION_INCOMPATIBLE` / `INVALID_ARGUMENT`); the work unit has no active execution (`CONFLICT`); retry constraints hold.

**AEVC-EXE-0002** The actor MUST hold every allowed effect kind's `required_actions` over every allowed resource selector (a grant's selectors must cover the requested selector); otherwise `FORBIDDEN`. The grant chains used are recorded on the execution.

**AEVC-EXE-0003** Reusing an idempotency key for the same active work-unit execution returns that execution; reusing it otherwise fails with `CONFLICT`.

## State machine and leases

`PENDING → ADMITTED → STARTING → RUNNING → SUCCEEDED`; `ADMITTED | STARTING | RUNNING → CANCELLED | FAILED | LOST`. Admission issues a lease `{id, execution, generation, provider, expires_at, heartbeat_interval_ms}` and moves the execution to `STARTING`; the first worker command moves it to `RUNNING`.

**AEVC-EXE-0004** Only the execution's actor or its provider principal, presenting the current lease ID, may heartbeat, submit effects, append observations, complete or fail the execution (`FORBIDDEN` otherwise).

**AEVC-EXE-0005** When a lease expires the execution MUST become `LOST` (runtime sweep before each command and periodically). For a resumable provider the sweep waits one additional lease period, during which only `HeartbeatExecution` with the exact lease ID and generation (the recovery proof) may renew it; other commands fail with `CONFLICT`.

**AEVC-EXE-0006** A `LOST` execution never becomes successful: every later command for it fails with `EXECUTION_LOST`. Recovery starts a new attempt with `retry_of` naming a `FAILED`, `LOST` or `CANCELLED` attempt of the same work unit; the new attempt's number increments and a `DERIVED_FROM` edge links the attempts.

## Effects

`SubmitEffectProposal{execution, lease, effect}`:

**AEVC-EXE-0007** The effect kind MUST be in the execution's allowed effects and its target within the allowed resources (`FORBIDDEN`); the target must be of the kind the effect declares (`INVALID_ARGUMENT`); and the execution actor MUST hold every `required_action` on the target resource (`FORBIDDEN`).

**AEVC-EXE-0008** The pack MUST still be `OPEN` at the execution's generation (`STALE_GENERATION` otherwise). The owning extension validates the proposal against the effects already applied to the same resource in this candidate; a rejected proposal is recorded (`effect.rejected`, result state `REJECTED`) and not applied. An accepted proposal is applied by the extension and appended to the candidate with its outcome and complete provenance (`effect.applied`, result state `APPLIED`).

Sealing freezes the candidate (changepack.md). Structural mutation during an execution creates a new generation, after which that execution can no longer contribute effects.
