//! Storage conformance profile against both reference backends, plus SQLite/CAS specifics.

use openaevc_store::conformance::{run_storage_profile, Fixture};
use openaevc_store::{MemoryStore, SqliteOptions, SqliteStore, Store, WriteBatch};

#[test]
fn memory_store_passes_storage_profile() {
    run_storage_profile(&|| Box::new(MemoryStore::new()) as Box<dyn Store>);
}

#[test]
fn sqlite_store_passes_storage_profile() {
    let dirs = std::sync::Mutex::new(Vec::new());
    run_storage_profile(&|| {
        let d = tempfile::tempdir().unwrap();
        let s = SqliteStore::open(
            d.path(),
            SqliteOptions {
                inline_threshold: 600,
                ..SqliteOptions::create()
            },
        )
        .unwrap();
        dirs.lock().unwrap().push(d);
        Box::new(s) as Box<dyn Store>
    });
}

fn open(dir: &std::path::Path) -> SqliteStore {
    SqliteStore::open(
        dir,
        SqliteOptions {
            inline_threshold: 600,
            ..SqliteOptions::create()
        },
    )
    .unwrap()
}

#[test]
fn sqlite_state_survives_restart() {
    let d = tempfile::tempdir().unwrap();
    let fx = Fixture::new();
    {
        let s = open(d.path());
        s.commit(fx.batch_with_events(2)).unwrap();
    }
    let s = open(d.path());
    assert_eq!(s.journal_head(&fx.ns).unwrap().unwrap().0, 2);
    assert!(s.get_object(&fx.large.digest()).unwrap().is_some());
    assert!(s.get_object(&fx.small.digest()).unwrap().is_some());
}

#[test]
fn tampered_cas_object_is_detected() {
    let d = tempfile::tempdir().unwrap();
    let fx = Fixture::new();
    let s = open(d.path());
    s.commit(fx.batch_with_events(1)).unwrap();
    let path = s.cas_path(&fx.large.digest());
    let mut bytes = std::fs::read(&path).unwrap();
    let n = bytes.len();
    bytes[n - 2] ^= 0x01;
    std::fs::write(&path, bytes).unwrap();
    let e = s.get_object(&fx.large.digest()).unwrap_err();
    assert_eq!(e.code, openaevc_protocol::ErrorCode::StorageIntegrityError);
    assert!(!s.verify_integrity().unwrap().ok());
}

#[test]
fn missing_cas_object_fails_reopen_closed() {
    let d = tempfile::tempdir().unwrap();
    let fx = Fixture::new();
    let path = {
        let s = open(d.path());
        s.commit(fx.batch_with_events(1)).unwrap();
        s.cas_path(&fx.large.digest())
    };
    std::fs::remove_file(path).unwrap();
    let e = SqliteStore::open(d.path(), SqliteOptions::create()).unwrap_err();
    assert_eq!(e.code, openaevc_protocol::ErrorCode::StorageIntegrityError);
}

#[test]
fn journal_tampering_in_database_is_detected() {
    let d = tempfile::tempdir().unwrap();
    let fx = Fixture::new();
    {
        let s = open(d.path());
        s.commit(fx.batch_with_events(3)).unwrap();
        s.tamper_event_body_for_tests(&fx.ns, 2, serde_json::json!({"forged": true}))
            .unwrap();
        assert!(!s.verify_integrity().unwrap().ok());
    }
}

#[test]
fn single_writer_lock() {
    let d = tempfile::tempdir().unwrap();
    let _a = open(d.path());
    let e = SqliteStore::open(d.path(), SqliteOptions::create()).unwrap_err();
    assert_eq!(e.code, openaevc_protocol::ErrorCode::Conflict);
}

#[test]
fn refuses_to_create_or_migrate_without_permission() {
    let d = tempfile::tempdir().unwrap();
    let e = SqliteStore::open(d.path(), SqliteOptions::default()).unwrap_err();
    assert_eq!(e.code, openaevc_protocol::ErrorCode::RecoveryRequired);
    drop(open(d.path()));
    SqliteStore::open(d.path(), SqliteOptions::default()).unwrap();
}

#[test]
fn newer_schema_is_refused() {
    let d = tempfile::tempdir().unwrap();
    {
        let s = open(d.path());
        s.set_schema_version_for_tests(999).unwrap();
    }
    let e = SqliteStore::open(d.path(), SqliteOptions::create()).unwrap_err();
    assert_eq!(e.code, openaevc_protocol::ErrorCode::RecoveryRequired);
}

mod crash {
    use super::*;
    use openaevc_store::Failpoint;

    fn crash_at(fp: Failpoint) -> (tempfile::TempDir, Fixture, bool) {
        let d = tempfile::tempdir().unwrap();
        let fx = Fixture::new();
        let s = open(d.path());
        s.commit(fx.batch_with_events(1)).unwrap();
        s.set_failpoint(Some(fp));
        let r = s.commit(fx.second_batch());
        assert!(r.is_err(), "failpoint {fp:?} must abort the commit");
        drop(s);
        (d, fx, fp == Failpoint::AfterSqliteCommit)
    }

    #[test]
    fn every_stage_recovers_to_all_or_nothing() {
        for fp in [
            Failpoint::AfterCasTempWrite,
            Failpoint::AfterCasRename,
            Failpoint::BeforeSqliteCommit,
            Failpoint::AfterSqliteCommit,
        ] {
            let (d, fx, committed) = crash_at(fp);
            let s = open(d.path());
            assert!(s.verify_integrity().unwrap().ok(), "{fp:?}");
            let head = s.journal_head(&fx.ns).unwrap().unwrap().0;
            let obj = s.get_object(&fx.second_large.digest()).unwrap();
            let agg = s.get_aggregate("test", &fx.agg_key).unwrap().unwrap();
            if committed {
                assert_eq!((head, obj.is_some(), agg.version), (2, true, 2), "{fp:?}");
            } else {
                assert_eq!((head, obj.is_some(), agg.version), (1, false, 1), "{fp:?}");
                // No temp files survive recovery.
                assert_eq!(
                    std::fs::read_dir(d.path().join("tmp")).unwrap().count(),
                    0,
                    "{fp:?}"
                );
                // Retrying the same batch now succeeds.
                s.commit(fx.second_batch()).unwrap();
            }
        }
    }
}

#[test]
fn garbage_collection_only_removes_unindexed_objects() {
    let d = tempfile::tempdir().unwrap();
    let fx = Fixture::new();
    let s = open(d.path());
    s.commit(fx.batch_with_events(1)).unwrap();
    s.set_failpoint(Some(openaevc_store::Failpoint::BeforeSqliteCommit));
    let _ = s.commit(fx.second_batch());
    s.set_failpoint(None);
    // The orphan CAS file from the aborted commit is collectable; indexed objects are not.
    let report = s.collect_garbage(std::time::Duration::ZERO).unwrap();
    assert_eq!(report.removed, 1);
    assert!(s.get_object(&fx.large.digest()).unwrap().is_some());
    assert!(s.verify_integrity().unwrap().ok());
    let _ = WriteBatch::default();
}
