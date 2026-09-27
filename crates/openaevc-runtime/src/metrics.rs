//! Runtime counters (OpenTelemetry/Prometheus-compatible text exposition). Telemetry is never
//! required for correctness.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

#[derive(Debug, Default)]
pub struct Metrics {
    commands: Mutex<BTreeMap<(String, String), u64>>,
    queries: AtomicU64,
    denials: AtomicU64,
    executions_lost: AtomicU64,
    extension_invocations: AtomicU64,
    extension_failures: AtomicU64,
}

impl Metrics {
    pub(crate) fn command(&self, name: &str, result: &str) {
        if let Ok(mut m) = self.commands.lock() {
            *m.entry((name.to_owned(), result.to_owned())).or_default() += 1;
        }
    }

    pub(crate) fn query(&self) {
        self.queries.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn denial(&self) {
        self.denials.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn lost(&self, n: u64) {
        self.executions_lost.fetch_add(n, Ordering::Relaxed);
    }

    pub(crate) fn extension(&self, ok: bool) {
        self.extension_invocations.fetch_add(1, Ordering::Relaxed);
        if !ok {
            self.extension_failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Count of commands with `name` and `result` (`ok` or an error code).
    pub fn commands(&self, name: &str, result: &str) -> u64 {
        self.commands
            .lock()
            .map(|m| {
                m.get(&(name.to_owned(), result.to_owned()))
                    .copied()
                    .unwrap_or(0)
            })
            .unwrap_or(0)
    }

    pub fn denials(&self) -> u64 {
        self.denials.load(Ordering::Relaxed)
    }

    /// Prometheus text exposition.
    pub fn prometheus(&self) -> String {
        let mut out = String::from("# TYPE openaevc_commands_total counter\n");
        if let Ok(m) = self.commands.lock() {
            for ((name, result), n) in m.iter() {
                out.push_str(&format!(
                    "openaevc_commands_total{{command=\"{name}\",result=\"{result}\"}} {n}\n"
                ));
            }
        }
        for (metric, v) in [
            ("openaevc_queries_total", &self.queries),
            ("openaevc_authorization_denials_total", &self.denials),
            ("openaevc_executions_lost_total", &self.executions_lost),
            (
                "openaevc_extension_invocations_total",
                &self.extension_invocations,
            ),
            (
                "openaevc_extension_failures_total",
                &self.extension_failures,
            ),
        ] {
            out.push_str(&format!(
                "# TYPE {metric} counter\n{metric} {}\n",
                v.load(Ordering::Relaxed)
            ));
        }
        out
    }
}
