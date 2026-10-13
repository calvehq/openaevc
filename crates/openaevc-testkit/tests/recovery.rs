//! Startup recovery fails closed on authoritative integrity failures.

use std::sync::Arc;

use openaevc::core::{FixedClock, UuidV7Ids};
use openaevc::protocol::*;
use openaevc::runtime::{Admin, Runtime, RuntimeConfig, RuntimeDeps};
use openaevc::store::{SqliteOptions, SqliteStore};
use openaevc_testkit::{admin_identity, runtime_key, Harness, Identity, EPOCH_2025};

fn reopen(dir: &std::path::Path) -> Result<Runtime, ProtocolError> {
    reopen_with(dir, runtime_key(), 1000)
}

fn reopen_with(
    dir: &std::path::Path,
    key: openaevc::crypto::SigningKey,
    checkpoint_interval: u64,
) -> Result<Runtime, ProtocolError> {
    let store = SqliteStore::open(dir, SqliteOptions::create())?;
    let clock = FixedClock::new(EPOCH_2025);
    let admin = admin_identity();
    Runtime::open(
        RuntimeDeps {
            store: Arc::new(store),
            clock: Arc::new(clock.clone()),
            ids: Arc::new(UuidV7Ids::new(Arc::new(clock))),
            signer: Arc::new(key),
            runtime_principal: "pri_agjdus24nvyadaareizuivlgp4".parse().unwrap(),
        },
        RuntimeConfig {
            admins: vec![Admin {
                id: admin.id(),
                public_key: admin.public_key(),
            }],
            checkpoint_interval,
            ..Default::default()
        },
    )
}

#[test]
fn tampered_journal_prevents_startup() {
    let dir = tempfile::tempdir().unwrap();
    let root = Identity::generate();
    let ns = {
        let h = Harness::sqlite(dir.path());
        let ns = h.create_namespace(&root);
        h.client(&root, ns)
            .cmd(Command::RegisterPrincipal {
                principal: Identity::generate().new_principal(),
            })
            .unwrap();
        ns
    };
    reopen(dir.path()).unwrap();
    {
        let store = SqliteStore::open(dir.path(), SqliteOptions::create()).unwrap();
        store
            .tamper_event_body_for_tests(&ns, 2, serde_json::json!({"forged": true}))
            .unwrap();
    }
    let e = reopen(dir.path()).unwrap_err();
    assert_eq!(e.code, ErrorCode::StorageIntegrityError);
}

fn journal_with_checkpoint(dir: &std::path::Path) -> NamespaceId {
    let store = SqliteStore::open(dir, SqliteOptions::create()).unwrap();
    let h = Harness::build(Arc::new(store), FixedClock::new(EPOCH_2025), |c| {
        c.checkpoint_interval = 2
    });
    let root = Identity::generate();
    let ns = h.create_namespace(&root);
    h.client(&root, ns)
        .cmd(Command::RegisterPrincipal {
            principal: Identity::generate().new_principal(),
        })
        .unwrap();
    ns
}

#[test]
fn checkpoint_from_another_runtime_key_prevents_startup() {
    let dir = tempfile::tempdir().unwrap();
    journal_with_checkpoint(dir.path());
    reopen_with(dir.path(), runtime_key(), 2).unwrap();
    let e = reopen_with(
        dir.path(),
        openaevc::crypto::SigningKey::from_seed([9; 32]),
        2,
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::StorageIntegrityError);
}

#[test]
fn tampered_checkpointed_event_prevents_startup() {
    let dir = tempfile::tempdir().unwrap();
    let ns = journal_with_checkpoint(dir.path());
    {
        let store = SqliteStore::open(dir.path(), SqliteOptions::create()).unwrap();
        store
            .tamper_event_body_for_tests(&ns, 2, serde_json::json!({"forged": true}))
            .unwrap();
    }
    let e = reopen_with(dir.path(), runtime_key(), 2).unwrap_err();
    assert_eq!(e.code, ErrorCode::StorageIntegrityError);
}
