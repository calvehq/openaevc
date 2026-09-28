# 0012. Host capabilities are protocol authorization, not OS confinement

- Status: accepted
- Date: 2026-09-28

## Context

Several documents described extensions as having "no storage access" and "only granted host capabilities", which reads as an OS containment guarantee. The reference host spawns extension processes under the runtime's own OS identity with no sandbox, and the manifest vocabulary includes `resource.write`, `network.connect` and `secret.read`, for which the host implements no host call, yet registration recorded them as granted.

## Decision

v1 adopts the weaker, true contract: host capabilities govern OpenAEVC-mediated privileged operations (host calls and accepted outputs); an extension executable is still subject only to the privileges of the OS identity that launched it. The protocol guarantees are that an extension cannot change runtime state except through validated outputs, cannot obtain ungranted host calls, out-of-scope resources or credentials through the protocol, and cannot hold the runtime past its deadline. OS containment is a deployment responsibility (docs/operations/README.md).

A host never grants a capability it implements no host call for; such requests are reported as `unsupported_host_capabilities` at registration and in `ListExtensions` (AEVC-EXT-0009). The capability names stay in the vocabulary so a future host can implement them without a protocol change.

## Consequences

Documentation no longer implies sandboxing. Hostile-extension tests prove what the host enforces (deadline, frame limits, capability checks, no hang from unread pipes or surviving descendants), not OS isolation. An OS-sandboxing host remains a compatible future option.
