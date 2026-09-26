# 0005. SQLite (WAL) plus filesystem content-addressed storage

- Status: accepted
- Date: 2026-09-26

## Decision
The reference store keeps metadata, aggregates, the journal and indexes in SQLite (WAL mode) and
large immutable objects in a filesystem CAS (`objects/sha256/ab/<hex>`), with small objects inline
in SQLite. CAS files are written temp→fsync→rename→verify *before* the SQLite transaction that
references them commits, so a committed row never references missing bytes. An in-memory backend
implements the same traits for tests. The SQLite schema is a generic aggregate table plus object,
index, journal and request tables; it is an implementation detail, never an integration API.

## Consequences
Orphan CAS files can exist after a crash; they are unreferenced and removed by the maintenance GC.
