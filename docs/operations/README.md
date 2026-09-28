# Operating `openaevcd`

## Install and initialize

```sh
openaevcd init --data-root /var/lib/openaevc --config-out /etc/openaevc/openaevcd.toml \
  --admin-key-out /etc/openaevc/admin.json
openaevcd check-config --config /etc/openaevc/openaevcd.toml
openaevcd run --config /etc/openaevc/openaevcd.toml
```

`init` creates the data-root schema and the runtime signing key (`runtime-key/ed25519.seed`, mode 0600) and never overwrites an existing key. The admin key file (`{id, seed, public_key}`) is the only credential that can create Namespaces; keep it offline.

## Configuration

`openaevcd print-effective-config` shows the file plus environment overrides with secrets redacted. Sections:

| Section | Keys |
| --- | --- |
| `[listen]` | `unix_socket` (default `<data_root>/openaevcd.sock`), `tcp` (loopback only), `[listen.tls]` `address`, `certificate`, `private_key` |
| `[runtime]` | `replay_window_ms`, `checkpoint_interval`, `lease_ms`, `heartbeat_interval_ms`, `audit_denials`, `max_page` |
| `[storage]` | `durability` (`full`/`normal`), `inline_threshold`, `auto_migrate` |
| `[extensions]` | `directories`, `deadline_ms`, `max_frame_bytes` |
| `[limits]` | `max_request_bytes`, `request_timeout_ms`, `event_buffer`, `slow_consumer_timeout_ms`, `tick_interval_ms`, `shutdown_grace_ms` |
| `[telemetry]` | `log_format` (`text`/`json`), `log_level`, `metrics` |

Non-loopback listeners must use TLS.

## Extensions and OS privileges

Registered extensions run as child processes with the daemon's OS identity. OpenAEVC's host capabilities restrict what an extension may ask the runtime for, not what the process may do on the machine: the reference host does not sandbox it (spec/security-model.md). For a deployment that must contain extension code:

- run `openaevcd` as a dedicated user, and keep extension directories writable only by administrators (digest pinning is checked before each spawn, not atomically with it);
- register only extensions you would run as that user, or wrap each extension entrypoint in a launcher that drops to a separate unprivileged user or sandbox (container, seccomp/AppArmor, sandbox-exec) with no access to the data root or `runtime-key/`;
- keep the admin key off the host.

## Health and metrics

- `GET /v1/health/live` — process is up.
- `GET /v1/health/ready` — accepting requests (false while starting or draining).
- `GET /v1/metrics` — Prometheus text: commands, queries, authorization denials, lost executions, extension invocations and failures.
- `GET /v1/info` — protocol, contract and implementation versions.

Logs are structured (`tracing`); secrets and payloads are never logged.

## Shutdown, backup and restore

`SIGTERM`/`SIGINT` stop accepting connections and drain for `shutdown_grace_ms`. For a consistent backup, stop the daemon and copy the whole data root; the data root is locked (`locks/runtime.lock`) while the daemon runs.

```sh
openaevc-inspect verify-journal /var/lib/openaevc   # journals, objects and indexes (daemon stopped)
```

On startup the runtime verifies the schema version, the committed objects and every journal from its last signed checkpoint. Corruption stops startup with `STORAGE_INTEGRITY_ERROR`; restore from backup — the runtime never repairs state silently.

## Upgrades

Data-root migrations are forward-only. A newer release refuses an older schema until started with `openaevcd run --migrate` (or `storage.auto_migrate = true`); an older release refuses a newer schema. See `COMPATIBILITY.md`.

## Garbage collection

```sh
openaevcd gc --config /etc/openaevc/openaevcd.toml --grace-seconds 3600   # daemon stopped
```

Removes bytes no Namespace indexes (crash leftovers, abandoned uploads) older than the grace period. Accepted history — every object indexed in any Namespace — is never removed.

## Conformance of a deployment

```sh
openaevc-conformance --profile FULL --target remote --endpoint 127.0.0.1:7878 \
  --admin-key admin.json --extensions /var/lib/openaevc/extensions --checkpoint-interval 1000
```

Run it against a staging instance: it creates Namespaces and objects.
