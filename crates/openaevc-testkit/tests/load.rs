//! Load and performance targets (engineering targets, not protocol guarantees). Ignored by
//! default; run with `cargo test --release -p openaevc-testkit --test load -- --ignored`.
//! `OPENAEVC_LOAD_PACKS` (default 50 000) packs are created and sealed: ≥100 000 journal events and
//! one candidate object each.

use std::time::{Duration, Instant};

use openaevc::protocol::*;
use std::sync::Arc;

use openaevc::core::FixedClock;
use openaevc::store::{Durability, SqliteOptions, SqliteStore, Store};
use openaevc_testkit::*;

fn percentile(v: &mut [Duration], p: f64) -> Duration {
    v.sort();
    v[((v.len() as f64 * p) as usize).min(v.len() - 1)]
}

#[test]
#[ignore = "load test: run explicitly in release mode"]
fn sustained_commands_stay_fast_and_consistent() {
    let n: usize = std::env::var("OPENAEVC_LOAD_PACKS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(50_000);
    let dir = tempfile::tempdir().unwrap();
    // Latency targets measure the runtime, not the disk: `durability = normal` leaves fsync to WAL
    // checkpoints. With `full`, every commit adds one fsync (≈1 ms on local SSD, far more on
    // virtualized disks).
    let store = Arc::new(
        SqliteStore::open(
            dir.path(),
            SqliteOptions {
                durability: Durability::Normal,
                ..SqliteOptions::create()
            },
        )
        .unwrap(),
    );
    let h = Harness::build(store.clone(), FixedClock::new(EPOCH_2025), |_| {});
    let root = Identity::generate();
    let ns = h.create_namespace(&root);
    let c = h.client(&root, ns);
    let (mut commands, mut queries) = (Vec::with_capacity(2 * n), Vec::with_capacity(n));
    for _ in 0..n {
        let t = Instant::now();
        let pack: PackId = receipt_id(
            &c.cmd(Command::CreateChangePack {
                spec: PackSpec::default(),
            })
            .unwrap(),
        );
        commands.push(t.elapsed());
        let t = Instant::now();
        c.cmd(Command::SealChangePack {
            pack,
            expected_generation: 1,
        })
        .unwrap();
        commands.push(t.elapsed());
        let t = Instant::now();
        c.query(Query::GetChangePack {
            pack,
            generation: None,
        })
        .unwrap();
        queries.push(t.elapsed());
    }
    // Accidental O(n) work per command (O(n²) overall) shows as latency growing with the
    // journal: compare the median of the first and last tenth of the run (in issue order).
    let tenth = (commands.len() / 10).max(1);
    let first = percentile(&mut commands[..tenth].to_vec(), 0.5);
    let last = percentile(&mut commands[commands.len() - tenth..].to_vec(), 0.5);
    println!("{n} packs: command median first tenth {first:?}, last tenth {last:?}");
    assert!(
        last <= first * 4 + Duration::from_millis(2),
        "command latency grows with history: {first:?} -> {last:?}"
    );
    let (p95_cmd, p50_query) = (
        percentile(&mut commands, 0.95),
        percentile(&mut queries, 0.50),
    );
    println!("{n} packs: command p95 {p95_cmd:?}, query p50 {p50_query:?}");

    // Pagination is bounded regardless of journal length, and resumes from any cursor.
    let page = c
        .query(Query::ListEvents {
            after: 0,
            limit: Some(u32::MAX),
            kinds: vec![],
        })
        .unwrap();
    assert!(page.as_array().unwrap().len() <= 1000);
    let tail = c
        .query(Query::ListEvents {
            after: 2 * n as u64 - 5,
            limit: None,
            kinds: vec![],
        })
        .unwrap();
    assert!(!tail.as_array().unwrap().is_empty());

    let report = store.verify_integrity().unwrap();
    assert!(report.ok(), "{:?}", report.problems);
    assert!(report.events as usize >= 2 * n);
    if !cfg!(debug_assertions) {
        assert!(
            p95_cmd < Duration::from_millis(25),
            "p95 command latency {p95_cmd:?}"
        );
        assert!(
            p50_query < Duration::from_millis(10),
            "p50 query latency {p50_query:?}"
        );
    }
}
