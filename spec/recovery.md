# Recovery

**AEVC-REC-0001** On startup the runtime MUST: verify the data-root schema version (refusing newer schemas and requiring an explicit migration for older ones); discard staged temporary object writes; verify that every committed object is present in the object store; verify each Namespace journal from its latest signed checkpoint (or genesis) to its head, including that the checkpoint matches the journal and is signed by the runtime's own key; and mark executions with expired leases `LOST`.

Startup checks object _presence_; object _bytes_ are re-hashed against their digest on every read, so a tampered object fails closed (`STORAGE_INTEGRITY_ERROR`) when first used. `openaevc-inspect verify-journal <data-root>` re-verifies every journal and re-hashes every object offline. A signed checkpoint proves the journal prefix to anyone who kept a copy of it (`GetJournalCheckpoint`); it cannot, by itself, detect an attacker with write access to the data root who also removes the checkpoint record.

**AEVC-REC-0002** If authoritative state integrity cannot be established (missing or tampered objects, broken journal chain, checkpoint mismatch) the runtime MUST fail closed (`STORAGE_INTEGRITY_ERROR`) and never silently reset or repair corrupt state.

**AEVC-REC-0003** State transitions are atomic with their audit events. Immutable bytes are written and verified before the transaction that references them commits, so no committed record ever references missing bytes; unreferenced bytes left by a crash are removed only by maintenance garbage collection.

**AEVC-REC-0004** Interrupted promotion never exposes a pack as promoted unless its PromotedPack, PromotionRecord and audit events are all present (promotion.md).

Snapshots are optional derived accelerators; they never override the journal. The reference runtime keeps every pack generation (no compaction) and never garbage-collects objects indexed in any Namespace.
