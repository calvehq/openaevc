//! Startup recovery fails closed on authoritative integrity failures.

use std::sync::Arc;

use openaevc_core::{FixedClock, UuidV7Ids};
use openaevc_protocol::*;
use openaevc_runtime::{Admin, Runtime, RuntimeConfig, RuntimeDeps};
use openaevc_store::{SqliteOptions, SqliteStore};
use openaevc_testkit::{admin_identity, runtime_key, Harness, Identity, EPOCH_2025};

fn reopen(dir: &std::path::Path) -> Result<Runtime, ProtocolError> {
    let store = SqliteStore::open(dir, SqliteOptions::create())?;
    let clock = FixedClock::new(EPOCH_2025);
    let admin = admin_identity();
    Runtime::open(
        RuntimeDeps {
            store: Arc::new(store),
            clock: Arc::new(clock.clone()),
            ids: Arc::new(UuidV7Ids::new(Arc::new(clock))),
            signer: Arc::new(runtime_key()),
            runtime_principal: "pri_agjdus24nvyadaareizuivlgp4".parse().unwrap(),
        },
        RuntimeConfig {
            admins: vec![Admin {
                id: admin.id(),
                public_key: admin.public_key(),
            }],
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
