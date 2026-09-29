//! Reference backend: SQLite (WAL) for metadata/aggregates/journal/indexes plus a filesystem
//! content-addressed store for immutable objects larger than the inline threshold.
//!
//! Data root layout (implementation detail, not protocol):
//!
//! ```text
//! <root>/runtime.sqlite3
//! <root>/objects/sha256/<first two hex>/<full hex>
//! <root>/tmp/
//! <root>/locks/runtime.lock
//! ```
//!
//! Commit protocol for a batch: (1) every new CAS object is written to `tmp/`, fsynced, renamed
//! into its digest path and read back for verification; (2) one SQLite transaction validates
//! the batch and inserts all rows; (3) directories are fsynced. A crash before (2) commits leaves
//! only unreferenced files (cleaned from `tmp/` at open, orphans removed by GC); a committed row
//! therefore never references missing bytes.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use openaevc_core::ImmutableObject;
use openaevc_protocol::{
    err, Digest, ErrorCode, Event, NamespaceId, ObjectKind, PrincipalId, ProtocolError, RequestId,
    Sequence, Timestamp,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::{
    validate_batch, AggregateRecord, BatchContext, GcReport, IntegrityReport, RequestRecord,
    Result, SnapshotRecord, Store, WriteBatch,
};

/// Current data-root schema version.
pub const SCHEMA_VERSION: u32 = 1;

const MIGRATIONS: &[&str] = &[
    // 1: initial schema.
    "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
     CREATE TABLE aggregates (
         kind TEXT NOT NULL, key TEXT NOT NULL, version INTEGER NOT NULL, body BLOB NOT NULL,
         PRIMARY KEY (kind, key));
     CREATE TABLE objects (
         digest TEXT PRIMARY KEY, kind TEXT NOT NULL, size INTEGER NOT NULL, inline_bytes BLOB);
     CREATE TABLE object_index (
         namespace TEXT NOT NULL, digest TEXT NOT NULL REFERENCES objects(digest), kind TEXT NOT NULL,
         PRIMARY KEY (namespace, digest));
     CREATE INDEX object_index_by_kind ON object_index (namespace, kind, digest);
     CREATE TABLE event_journal (
         namespace TEXT NOT NULL, sequence INTEGER NOT NULL, event_id TEXT NOT NULL,
         kind TEXT NOT NULL, hash TEXT NOT NULL, previous_hash TEXT NOT NULL, body BLOB NOT NULL,
         PRIMARY KEY (namespace, sequence));
     CREATE TABLE request_nonce_window (
         principal TEXT NOT NULL, request_id TEXT NOT NULL, nonce TEXT NOT NULL,
         envelope_digest TEXT NOT NULL, receipt TEXT, issued_at_ns INTEGER NOT NULL,
         PRIMARY KEY (principal, request_id));
     CREATE UNIQUE INDEX request_nonce_unique ON request_nonce_window (principal, nonce);
     CREATE INDEX request_issued_at ON request_nonce_window (issued_at_ns);
     CREATE TABLE runtime_snapshots (
         namespace TEXT NOT NULL, sequence INTEGER NOT NULL, event_hash TEXT NOT NULL,
         projection_digest TEXT NOT NULL, PRIMARY KEY (namespace, sequence));",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Durability {
    /// SQLite `synchronous=FULL`: a commit is durable once it returns.
    Full,
    /// SQLite `synchronous=NORMAL`: faster, may lose the latest commits on power loss but never
    /// corrupts committed history. CAS files and directories are fsynced in both modes, so a
    /// row that survives power loss never references bytes that did not.
    Normal,
}

#[derive(Debug, Clone)]
pub struct SqliteOptions {
    /// Initialize a new data root if none exists.
    pub create: bool,
    /// Apply pending forward migrations.
    pub migrate: bool,
    /// Objects larger than this many bytes are stored in the CAS instead of inline.
    pub inline_threshold: usize,
    pub durability: Durability,
}

impl Default for SqliteOptions {
    fn default() -> Self {
        SqliteOptions {
            create: false,
            migrate: false,
            inline_threshold: 16 * 1024,
            durability: Durability::Full,
        }
    }
}

impl SqliteOptions {
    /// Create-if-missing and migrate.
    pub fn create() -> Self {
        SqliteOptions {
            create: true,
            migrate: true,
            ..Self::default()
        }
    }
}

/// Crash-injection points inside `commit` (enabled by the `fault-injection` feature).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failpoint {
    AfterCasTempWrite,
    AfterCasRename,
    BeforeSqliteCommit,
    AfterSqliteCommit,
}

pub struct SqliteStore {
    root: PathBuf,
    conn: Mutex<Connection>,
    opts: SqliteOptions,
    _lock: File,
    failpoint: Mutex<Option<Failpoint>>,
}

impl std::fmt::Debug for SqliteStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteStore").finish_non_exhaustive()
    }
}

fn db_err(e: rusqlite::Error) -> ProtocolError {
    // Never leak SQL text or paths into protocol errors.
    match e {
        rusqlite::Error::SqliteFailure(f, _)
            if f.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            ProtocolError::new(ErrorCode::Conflict, "storage constraint violated")
        }
        rusqlite::Error::SqliteFailure(f, _)
            if matches!(
                f.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            ) =>
        {
            ProtocolError::new(ErrorCode::Conflict, "storage busy")
        }
        _ => err::internal("storage operation failed"),
    }
}

fn io_err(_: std::io::Error) -> ProtocolError {
    err::internal("storage I/O failed")
}

fn parse<T: std::str::FromStr>(s: &str) -> Result<T> {
    s.parse()
        .map_err(|_| err::integrity("stored value is malformed"))
}

fn fsync_dir(path: &Path) {
    // Directory fsync is unsupported on some platforms (Windows); best effort.
    if let Ok(d) = File::open(path) {
        let _ = d.sync_all();
    }
}

impl SqliteStore {
    pub fn open(root: &Path, opts: SqliteOptions) -> Result<Self> {
        let db_path = root.join("runtime.sqlite3");
        let fresh = !db_path.exists();
        if fresh && !opts.create {
            return Err(ProtocolError::new(
                ErrorCode::RecoveryRequired,
                "data root is not initialized",
            ));
        }
        for dir in ["objects/sha256", "tmp", "locks"] {
            fs::create_dir_all(root.join(dir)).map_err(io_err)?;
        }
        let lock = File::options()
            .create(true)
            .truncate(false)
            .write(true)
            .open(root.join("locks/runtime.lock"))
            .map_err(io_err)?;
        lock.try_lock().map_err(|_| {
            ProtocolError::new(
                ErrorCode::Conflict,
                "data root is in use by another runtime process",
            )
        })?;

        let mut conn = Connection::open(&db_path).map_err(db_err)?;
        let sync = if opts.durability == Durability::Full {
            "FULL"
        } else {
            "NORMAL"
        };
        conn.execute_batch(&format!(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous={sync}; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;"
        ))
        .map_err(db_err)?;

        let has_meta: bool = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='meta'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map_err(db_err)?
            > 0;
        let version: u32 = if has_meta {
            conn.query_row(
                "SELECT value FROM meta WHERE key='schema_version'",
                [],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .map_err(db_err)?
            .map(|v| parse(&v))
            .transpose()?
            .unwrap_or(0)
        } else {
            0
        };
        if version > SCHEMA_VERSION {
            return Err(ProtocolError::new(
                ErrorCode::RecoveryRequired,
                format!("data root schema {version} is newer than supported {SCHEMA_VERSION}; refusing to downgrade"),
            ));
        }
        if version < SCHEMA_VERSION {
            if !(opts.migrate || (fresh && opts.create)) {
                return Err(ProtocolError::new(
                    ErrorCode::RecoveryRequired,
                    format!("data root schema {version} requires migration to {SCHEMA_VERSION}"),
                ));
            }
            let tx = conn.transaction().map_err(db_err)?;
            for (i, m) in MIGRATIONS.iter().enumerate().skip(version as usize) {
                tx.execute_batch(m).map_err(db_err)?;
                tx.execute(
                    "INSERT INTO meta(key, value) VALUES ('schema_version', ?1)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    params![(i + 1).to_string()],
                )
                .map_err(db_err)?;
            }
            tx.commit().map_err(db_err)?;
        }

        let store = SqliteStore {
            root: root.to_path_buf(),
            conn: Mutex::new(conn),
            opts,
            _lock: lock,
            failpoint: Mutex::new(None),
        };
        store.recover()?;
        Ok(store)
    }

    /// Startup recovery: drop staged temp files, then fail closed if any committed object is
    /// missing from the CAS.
    fn recover(&self) -> Result<()> {
        for entry in fs::read_dir(self.root.join("tmp")).map_err(io_err)? {
            let _ = fs::remove_file(entry.map_err(io_err)?.path());
        }
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare("SELECT digest, size FROM objects WHERE inline_bytes IS NULL")
            .map_err(db_err)?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
            .map_err(db_err)?;
        for row in rows {
            let (d, size) = row.map_err(db_err)?;
            let digest: Digest = parse(&d)?;
            let ok = fs::metadata(self.cas_path(&digest))
                .map(|m| m.len() == size as u64)
                .unwrap_or(false);
            if !ok {
                return Err(err::integrity(format!(
                    "committed object {digest} is missing or truncated in the object store"
                )));
            }
        }
        Ok(())
    }

    fn conn(&self) -> Result<MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| err::internal("store lock poisoned"))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Filesystem path of a CAS object.
    pub fn cas_path(&self, d: &Digest) -> PathBuf {
        let hex = d.hex();
        self.root.join("objects/sha256").join(&hex[..2]).join(hex)
    }

    fn hit(&self, fp: Failpoint) -> Result<()> {
        let armed = *self
            .failpoint
            .lock()
            .map_err(|_| err::internal("lock poisoned"))?;
        if armed == Some(fp) {
            return Err(err::internal(format!("injected crash at {fp:?}")));
        }
        Ok(())
    }

    #[cfg(feature = "fault-injection")]
    #[doc(hidden)]
    pub fn set_failpoint(&self, fp: Option<Failpoint>) {
        if let Ok(mut g) = self.failpoint.lock() {
            *g = fp;
        }
    }

    #[cfg(feature = "fault-injection")]
    #[doc(hidden)]
    pub fn tamper_event_body_for_tests(
        &self,
        ns: &NamespaceId,
        seq: Sequence,
        body: serde_json::Value,
    ) -> Result<()> {
        let conn = self.conn()?;
        let raw: Vec<u8> = conn
            .query_row(
                "SELECT body FROM event_journal WHERE namespace=?1 AND sequence=?2",
                params![ns.to_string(), seq as i64],
                |r| r.get(0),
            )
            .map_err(db_err)?;
        let mut e: Event = serde_json::from_slice(&raw).map_err(|_| err::integrity("bad event"))?;
        e.body = body;
        conn.execute(
            "UPDATE event_journal SET body=?3 WHERE namespace=?1 AND sequence=?2",
            params![
                ns.to_string(),
                seq as i64,
                serde_json::to_vec(&e).map_err(|_| err::internal("encode"))?
            ],
        )
        .map_err(db_err)?;
        Ok(())
    }

    #[cfg(feature = "fault-injection")]
    #[doc(hidden)]
    pub fn set_schema_version_for_tests(&self, v: u32) -> Result<()> {
        self.conn()?
            .execute(
                "UPDATE meta SET value=?1 WHERE key='schema_version'",
                params![v.to_string()],
            )
            .map_err(db_err)?;
        Ok(())
    }

    /// Writes an object into the CAS (idempotent; repairs a corrupt existing file). The file
    /// and its directory entries are durable before this returns, in every durability mode:
    /// the referencing SQLite row may commit right after.
    fn stage_cas(&self, o: &ImmutableObject) -> Result<()> {
        let final_path = self.cas_path(&o.digest());
        let dir = final_path
            .parent()
            .ok_or_else(|| err::internal("bad CAS path"))?;
        if let Ok(existing) = fs::read(&final_path) {
            if openaevc_crypto::sha256(&existing) == o.digest() {
                // May be left by a crash before its fsyncs completed.
                fs::OpenOptions::new()
                    .write(true)
                    .open(&final_path)
                    .and_then(|f| f.sync_all())
                    .map_err(io_err)?;
                fsync_dir(dir);
                return Ok(());
            }
        }
        if !dir.exists() {
            fs::create_dir_all(dir).map_err(io_err)?;
            if let Some(parent) = dir.parent() {
                fsync_dir(parent);
            }
        }
        let tmp =
            self.root
                .join("tmp")
                .join(format!("{}.{}", o.digest().hex(), std::process::id()));
        {
            let mut f = File::create(&tmp).map_err(io_err)?;
            f.write_all(o.bytes()).map_err(io_err)?;
            f.sync_all().map_err(io_err)?;
        }
        self.hit(Failpoint::AfterCasTempWrite)?;
        fs::rename(&tmp, &final_path).map_err(io_err)?;
        self.hit(Failpoint::AfterCasRename)?;
        let back = fs::read(&final_path).map_err(io_err)?;
        if openaevc_crypto::sha256(&back) != o.digest() {
            return Err(err::integrity(format!(
                "object {} failed read-back verification",
                o.digest()
            )));
        }
        fsync_dir(dir);
        Ok(())
    }

    fn load_object(&self, conn: &Connection, digest: &Digest) -> Result<Option<ImmutableObject>> {
        let row: Option<Option<Vec<u8>>> = conn
            .query_row(
                "SELECT inline_bytes FROM objects WHERE digest=?1",
                params![digest.to_string()],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_err)?;
        let Some(inline) = row else { return Ok(None) };
        let bytes = match inline {
            Some(b) => b,
            None => fs::read(self.cas_path(digest)).map_err(|_| {
                err::integrity(format!("object {digest} is missing from the object store"))
            })?,
        };
        ImmutableObject::from_bytes(&bytes, Some(*digest))
            .map(Some)
            .map_err(|e| {
                err::integrity(format!(
                    "object {digest} failed verification: {}",
                    e.message
                ))
            })
    }

    /// Maintenance GC: removes objects not indexed in any Namespace and orphan CAS files older
    /// than `grace`. Two scans: candidates are re-checked inside the deleting transaction.
    /// Indexed objects (all accepted history) are never removed.
    pub fn collect_garbage(&self, grace: Duration) -> Result<GcReport> {
        let mut report = GcReport::default();
        let mut conn = self.conn()?;
        let tx = conn.transaction().map_err(db_err)?;
        let candidates: Vec<(String, bool)> = {
            let mut stmt = tx
                .prepare("SELECT digest, inline_bytes IS NULL FROM objects o WHERE NOT EXISTS (SELECT 1 FROM object_index i WHERE i.digest = o.digest)")
                .map_err(db_err)?;
            let rows = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .map_err(db_err)?;
            rows.collect::<std::result::Result<_, _>>()
                .map_err(db_err)?
        };
        let mut unlink = Vec::new();
        for (d, in_cas) in &candidates {
            let still = tx
                .query_row(
                    "SELECT count(*) FROM object_index WHERE digest=?1",
                    params![d],
                    |r| r.get::<_, i64>(0),
                )
                .map_err(db_err)?;
            if still == 0 {
                tx.execute("DELETE FROM objects WHERE digest=?1", params![d])
                    .map_err(db_err)?;
                if *in_cas {
                    unlink.push(self.cas_path(&parse(d)?));
                }
                report.removed += 1;
            }
        }
        tx.commit().map_err(db_err)?;
        // Only after the rows are gone: a crash in between leaves orphan files, never rows
        // without bytes.
        for path in unlink {
            let _ = fs::remove_file(path);
        }
        // Orphan CAS files (no row at all), e.g. from a crash between rename and commit.
        let now = SystemTime::now();
        for shard in fs::read_dir(self.root.join("objects/sha256")).map_err(io_err)? {
            let shard = shard.map_err(io_err)?.path();
            for f in fs::read_dir(&shard).map_err(io_err)? {
                let f = f.map_err(io_err)?;
                report.scanned += 1;
                let name = f.file_name().to_string_lossy().into_owned();
                let known = conn
                    .query_row(
                        "SELECT count(*) FROM objects WHERE digest=?1",
                        params![format!("sha256:{name}")],
                        |r| r.get::<_, i64>(0),
                    )
                    .map_err(db_err)?
                    > 0;
                let old = f
                    .metadata()
                    .and_then(|m| m.modified())
                    .map(|m| now.duration_since(m).unwrap_or_default() >= grace)
                    .unwrap_or(false);
                if !known && old {
                    let _ = fs::remove_file(f.path());
                    report.removed += 1;
                }
            }
        }
        Ok(report)
    }
}

struct TxContext<'a>(&'a Transaction<'a>);

impl BatchContext for TxContext<'_> {
    fn version(&self, kind: &str, key: &str) -> Result<u64> {
        Ok(self
            .0
            .query_row(
                "SELECT version FROM aggregates WHERE kind=?1 AND key=?2",
                params![kind, key],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .map_err(db_err)?
            .unwrap_or(0) as u64)
    }
    fn head(&self, ns: &NamespaceId) -> Result<Option<(Sequence, Digest)>> {
        head(self.0, ns)
    }
    fn has_object(&self, d: &Digest) -> Result<bool> {
        exists(
            self.0,
            "SELECT count(*) FROM objects WHERE digest=?1",
            &d.to_string(),
        )
    }
    fn has_request(&self, p: &PrincipalId, r: &RequestId) -> Result<bool> {
        Ok(self
            .0
            .query_row(
                "SELECT count(*) FROM request_nonce_window WHERE principal=?1 AND request_id=?2",
                params![p.to_string(), r.to_string()],
                |x| x.get::<_, i64>(0),
            )
            .map_err(db_err)?
            > 0)
    }
    fn nonce_used(&self, p: &PrincipalId, n: &str) -> Result<bool> {
        nonce_used(self.0, p, n)
    }
}

fn exists(c: &Connection, sql: &str, arg: &str) -> Result<bool> {
    Ok(c.query_row(sql, params![arg], |r| r.get::<_, i64>(0))
        .map_err(db_err)?
        > 0)
}

fn nonce_used(c: &Connection, p: &PrincipalId, n: &str) -> Result<bool> {
    Ok(c.query_row(
        "SELECT count(*) FROM request_nonce_window WHERE principal=?1 AND nonce=?2",
        params![p.to_string(), n],
        |r| r.get::<_, i64>(0),
    )
    .map_err(db_err)?
        > 0)
}

fn head(c: &Connection, ns: &NamespaceId) -> Result<Option<(Sequence, Digest)>> {
    c.query_row(
        "SELECT sequence, hash FROM event_journal WHERE namespace=?1 ORDER BY sequence DESC LIMIT 1",
        params![ns.to_string()],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
    )
    .optional()
    .map_err(db_err)?
    .map(|(s, h)| Ok((s as u64, parse(&h)?)))
    .transpose()
}

fn decode_event(raw: &[u8]) -> Result<Event> {
    serde_json::from_slice(raw).map_err(|_| err::integrity("stored journal event is malformed"))
}

fn ts_nanos(t: Timestamp) -> i64 {
    t.unix_nanos()
        .clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

impl Store for SqliteStore {
    fn get_aggregate(&self, kind: &str, key: &str) -> Result<Option<AggregateRecord>> {
        let conn = self.conn()?;
        conn.query_row(
            "SELECT version, body FROM aggregates WHERE kind=?1 AND key=?2",
            params![kind, key],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
        )
        .optional()
        .map_err(db_err)?
        .map(|(v, b)| {
            Ok(AggregateRecord {
                version: v as u64,
                body: serde_json::from_slice(&b)
                    .map_err(|_| err::integrity("stored aggregate is malformed"))?,
            })
        })
        .transpose()
    }

    fn list_aggregates(&self, kind: &str, prefix: &str) -> Result<Vec<(String, AggregateRecord)>> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare("SELECT key, version, body FROM aggregates WHERE kind=?1 AND key >= ?2 ORDER BY key")
            .map_err(db_err)?;
        let rows = stmt
            .query_map(params![kind, prefix], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(db_err)?;
        let mut out = Vec::new();
        for row in rows {
            let (k, v, b) = row.map_err(db_err)?;
            if !k.starts_with(prefix) {
                break;
            }
            let body = serde_json::from_slice(&b)
                .map_err(|_| err::integrity("stored aggregate is malformed"))?;
            out.push((
                k,
                AggregateRecord {
                    version: v as u64,
                    body,
                },
            ));
        }
        Ok(out)
    }

    fn get_object(&self, digest: &Digest) -> Result<Option<ImmutableObject>> {
        let conn = self.conn()?;
        self.load_object(&conn, digest)
    }

    fn has_object(&self, digest: &Digest) -> Result<bool> {
        exists(
            &*self.conn()?,
            "SELECT count(*) FROM objects WHERE digest=?1",
            &digest.to_string(),
        )
    }

    fn is_indexed(&self, ns: &NamespaceId, digest: &Digest) -> Result<bool> {
        let conn = self.conn()?;
        Ok(conn
            .query_row(
                "SELECT count(*) FROM object_index WHERE namespace=?1 AND digest=?2",
                params![ns.to_string(), digest.to_string()],
                |r| r.get::<_, i64>(0),
            )
            .map_err(db_err)?
            > 0)
    }

    fn list_index(
        &self,
        ns: &NamespaceId,
        kind: Option<ObjectKind>,
        after: Option<Digest>,
        limit: usize,
    ) -> Result<Vec<(Digest, ObjectKind)>> {
        let conn = self.conn()?;
        let after = after.map(|d| d.to_string()).unwrap_or_default();
        let kind_s = kind.map(|k| k.as_str().to_owned());
        let mut stmt = conn
            .prepare(
                "SELECT digest, kind FROM object_index WHERE namespace=?1 AND digest > ?2
                 AND (?3 IS NULL OR kind = ?3) ORDER BY digest LIMIT ?4",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map(params![ns.to_string(), after, kind_s, limit as i64], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })
            .map_err(db_err)?;
        let mut out = Vec::new();
        for row in rows {
            let (d, k) = row.map_err(db_err)?;
            let kind: ObjectKind = serde_json::from_value(serde_json::Value::String(k))
                .map_err(|_| err::integrity("bad kind"))?;
            out.push((parse(&d)?, kind));
        }
        Ok(out)
    }

    fn journal_head(&self, ns: &NamespaceId) -> Result<Option<(Sequence, Digest)>> {
        head(&*self.conn()?, ns)
    }

    fn read_events(&self, ns: &NamespaceId, after: Sequence, limit: usize) -> Result<Vec<Event>> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare("SELECT body FROM event_journal WHERE namespace=?1 AND sequence > ?2 ORDER BY sequence LIMIT ?3")
            .map_err(db_err)?;
        let rows = stmt
            .query_map(params![ns.to_string(), after as i64, limit as i64], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .map_err(db_err)?;
        rows.map(|r| decode_event(&r.map_err(db_err)?)).collect()
    }

    fn get_request(&self, p: &PrincipalId, r: &RequestId) -> Result<Option<RequestRecord>> {
        let conn = self.conn()?;
        conn.query_row(
            "SELECT nonce, envelope_digest, receipt, issued_at_ns FROM request_nonce_window WHERE principal=?1 AND request_id=?2",
            params![p.to_string(), r.to_string()],
            |x| Ok((x.get::<_, String>(0)?, x.get::<_, String>(1)?, x.get::<_, Option<String>>(2)?, x.get::<_, i64>(3)?)),
        )
        .optional()
        .map_err(db_err)?
        .map(|(nonce, env, receipt, at)| {
            Ok(RequestRecord {
                principal: *p,
                request_id: *r,
                nonce,
                envelope_digest: parse(&env)?,
                receipt: receipt.map(|x| parse(&x)).transpose()?,
                issued_at: Timestamp::from_unix_nanos(i128::from(at)),
            })
        })
        .transpose()
    }

    fn nonce_used(&self, p: &PrincipalId, n: &str) -> Result<bool> {
        nonce_used(&*self.conn()?, p, n)
    }

    fn prune_requests(&self, before: Timestamp) -> Result<usize> {
        self.conn()?
            .execute(
                "DELETE FROM request_nonce_window WHERE issued_at_ns < ?1",
                params![ts_nanos(before)],
            )
            .map_err(db_err)
    }

    fn latest_snapshot(&self, ns: &NamespaceId) -> Result<Option<SnapshotRecord>> {
        let conn = self.conn()?;
        conn.query_row(
            "SELECT sequence, event_hash, projection_digest FROM runtime_snapshots WHERE namespace=?1 ORDER BY sequence DESC LIMIT 1",
            params![ns.to_string()],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)),
        )
        .optional()
        .map_err(db_err)?
        .map(|(s, h, p)| Ok(SnapshotRecord { namespace: *ns, sequence: s as u64, event_hash: parse(&h)?, projection_digest: parse(&p)? }))
        .transpose()
    }

    fn namespaces(&self) -> Result<Vec<NamespaceId>> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare("SELECT DISTINCT namespace FROM event_journal ORDER BY namespace")
            .map_err(db_err)?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(db_err)?;
        rows.map(|r| parse(&r.map_err(db_err)?)).collect()
    }

    fn commit(&self, b: WriteBatch) -> Result<()> {
        let mut conn = self.conn()?;
        // Stage CAS objects before the transaction that references them.
        for o in &b.objects {
            let known = exists(
                &conn,
                "SELECT count(*) FROM objects WHERE digest=?1",
                &o.digest().to_string(),
            )?;
            if !known && o.bytes().len() > self.opts.inline_threshold {
                self.stage_cas(o)?;
            }
        }
        let tx = conn.transaction().map_err(db_err)?;
        validate_batch(&b, &TxContext(&tx))?;
        for a in &b.aggregates {
            let body = serde_json::to_vec(&a.body)
                .map_err(|_| err::internal("aggregate encoding failed"))?;
            tx.execute(
                "INSERT INTO aggregates(kind, key, version, body) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(kind, key) DO UPDATE SET version = excluded.version, body = excluded.body",
                params![a.kind, a.key, (a.expected_version + 1) as i64, body],
            )
            .map_err(db_err)?;
        }
        for o in &b.objects {
            let inline =
                (o.bytes().len() <= self.opts.inline_threshold).then(|| o.bytes().to_vec());
            tx.execute(
                "INSERT OR IGNORE INTO objects(digest, kind, size, inline_bytes) VALUES (?1, ?2, ?3, ?4)",
                params![o.digest().to_string(), o.kind().as_str(), o.bytes().len() as i64, inline],
            )
            .map_err(db_err)?;
        }
        for i in &b.index {
            tx.execute(
                "INSERT OR IGNORE INTO object_index(namespace, digest, kind) VALUES (?1, ?2, ?3)",
                params![
                    i.namespace.to_string(),
                    i.digest.to_string(),
                    i.kind.as_str()
                ],
            )
            .map_err(db_err)?;
        }
        for e in &b.events {
            let body = serde_json::to_vec(e).map_err(|_| err::internal("event encoding failed"))?;
            tx.execute(
                "INSERT INTO event_journal(namespace, sequence, event_id, kind, hash, previous_hash, body)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![e.namespace.to_string(), e.sequence as i64, e.id.to_string(), e.kind, e.hash.to_string(), e.previous_hash.to_string(), body],
            )
            .map_err(db_err)?;
        }
        for r in &b.requests {
            tx.execute(
                "INSERT INTO request_nonce_window(principal, request_id, nonce, envelope_digest, receipt, issued_at_ns)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    r.principal.to_string(),
                    r.request_id.to_string(),
                    r.nonce,
                    r.envelope_digest.to_string(),
                    r.receipt.map(|d| d.to_string()),
                    ts_nanos(r.issued_at)
                ],
            )
            .map_err(db_err)?;
        }
        for s in &b.snapshots {
            tx.execute(
                "INSERT OR REPLACE INTO runtime_snapshots(namespace, sequence, event_hash, projection_digest) VALUES (?1, ?2, ?3, ?4)",
                params![s.namespace.to_string(), s.sequence as i64, s.event_hash.to_string(), s.projection_digest.to_string()],
            )
            .map_err(db_err)?;
        }
        self.hit(Failpoint::BeforeSqliteCommit)?;
        tx.commit().map_err(db_err)?;
        self.hit(Failpoint::AfterSqliteCommit)?;
        Ok(())
    }

    fn verify_integrity(&self) -> Result<IntegrityReport> {
        let mut report = IntegrityReport::default();
        let namespaces = self.namespaces()?;
        report.namespaces = namespaces.len();
        for ns in &namespaces {
            let mut after = 0;
            let mut hash = Digest::ZERO;
            loop {
                let events = self.read_events(ns, after, 1000)?;
                if events.is_empty() {
                    break;
                }
                report.events += events.len() as u64;
                match openaevc_core::events::verify_chain(&events, after, hash) {
                    Ok((s, h)) => {
                        after = s;
                        hash = h;
                    }
                    Err(e) => {
                        report.problems.push(format!("{ns}: {}", e.message));
                        break;
                    }
                }
            }
            if let Some(snap) = self.latest_snapshot(ns)? {
                let conn = self.conn()?;
                let at: Option<String> = conn
                    .query_row(
                        "SELECT hash FROM event_journal WHERE namespace=?1 AND sequence=?2",
                        params![ns.to_string(), snap.sequence as i64],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(db_err)?;
                if at.as_deref() != Some(snap.event_hash.to_string().as_str()) {
                    report.problems.push(format!(
                        "{ns}: snapshot at {} does not match the journal",
                        snap.sequence
                    ));
                }
            }
        }
        let digests: Vec<String> = {
            let conn = self.conn()?;
            let mut stmt = conn.prepare("SELECT digest FROM objects").map_err(db_err)?;
            let rows = stmt.query_map([], |r| r.get(0)).map_err(db_err)?;
            rows.collect::<std::result::Result<_, _>>()
                .map_err(db_err)?
        };
        for d in digests {
            report.objects += 1;
            if let Err(e) = self.get_object(&parse(&d)?) {
                report.problems.push(e.message);
            }
        }
        Ok(report)
    }
}
