//! Clock and ID-generator abstractions. The runtime never reads the system clock or entropy
//! directly, so tests and conformance runs can be deterministic.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

use crate::protocol::Timestamp;
use rand_core::RngCore;

pub trait Clock: Send + Sync {
    fn now(&self) -> Timestamp;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Timestamp::from_unix_nanos(d.as_nanos() as i128)
    }
}

/// Manually advanced clock for tests; clones share the same time.
#[derive(Debug, Clone)]
pub struct FixedClock(Arc<AtomicI64>);

impl FixedClock {
    pub fn new(unix_nanos: i64) -> Self {
        FixedClock(Arc::new(AtomicI64::new(unix_nanos)))
    }

    pub fn advance_millis(&self, ms: i64) {
        self.0.fetch_add(ms * 1_000_000, Ordering::SeqCst);
    }

    pub fn set(&self, unix_nanos: i64) {
        self.0.store(unix_nanos, Ordering::SeqCst);
    }
}

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_unix_nanos(i128::from(self.0.load(Ordering::SeqCst)))
    }
}

/// Source of raw UUIDv7 bytes; typed IDs are built from them.
pub trait IdGenerator: Send + Sync {
    fn next_bytes(&self) -> [u8; 16];
}

/// Convenience: `ids.next::<ChangePackId>()`.
pub trait IdGeneratorExt {
    fn next<T: FromUuid>(&self) -> T;
}

impl<G: IdGenerator + ?Sized> IdGeneratorExt for G {
    fn next<T: FromUuid>(&self) -> T {
        T::from_uuid(self.next_bytes())
    }
}

/// Typed IDs constructible from generator output (always valid UUIDv7 bytes).
pub trait FromUuid {
    fn from_uuid(b: [u8; 16]) -> Self;
}

macro_rules! from_uuid {
    ($($t:ident),*) => {$(
        impl FromUuid for crate::protocol::$t {
            fn from_uuid(b: [u8; 16]) -> Self {
                crate::protocol::$t::from_bytes(b).expect("generators produce UUIDv7 bytes")
            }
        }
    )*};
}

from_uuid!(
    NamespaceId,
    PrincipalId,
    GrantId,
    ChangePackId,
    RevisionPackId,
    ExecutionId,
    ObservationId,
    EvidenceId,
    VerificationId,
    EvaluationId,
    PromotionId,
    BaselineId,
    EventId,
    WorkUnitId,
    LeaseId,
    RequestId,
    EffectId,
    RuntimeInstanceId
);

fn uuidv7(ms: u64, rand: [u8; 10]) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..6].copy_from_slice(&ms.to_be_bytes()[2..]);
    b[6..].copy_from_slice(&rand);
    b[6] = 0x70 | (b[6] & 0x0f);
    b[8] = 0x80 | (b[8] & 0x3f);
    b
}

/// UUIDv7 from the clock's milliseconds plus OS entropy.
pub struct UuidV7Ids {
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for UuidV7Ids {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UuidV7Ids")
    }
}

impl UuidV7Ids {
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        UuidV7Ids { clock }
    }
}

impl IdGenerator for UuidV7Ids {
    fn next_bytes(&self) -> [u8; 16] {
        let ms = (self.clock.now().unix_nanos() / 1_000_000).max(0) as u64;
        let mut rand = [0u8; 10];
        rand_core::OsRng.fill_bytes(&mut rand);
        uuidv7(ms, rand)
    }
}

/// Deterministic UUIDv7-shaped IDs from a seed and counter (tests, fixtures).
#[derive(Debug)]
pub struct SequentialIds {
    seed: u64,
    counter: AtomicU64,
}

impl SequentialIds {
    pub fn new(seed: u64) -> Self {
        SequentialIds {
            seed,
            counter: AtomicU64::new(0),
        }
    }
}

impl IdGenerator for SequentialIds {
    fn next_bytes(&self) -> [u8; 16] {
        let n = self.counter.fetch_add(1, Ordering::SeqCst) + 1;
        let mut rand = [0u8; 10];
        rand[..2].copy_from_slice(&(self.seed as u16).to_be_bytes());
        rand[2..].copy_from_slice(&n.to_be_bytes());
        uuidv7(1_700_000_000_000 + n, rand)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ChangePackId;

    #[test]
    fn uuidv7_ids_are_valid_and_time_ordered() {
        let clock = FixedClock::new(1_700_000_000_000_000_000);
        let ids = UuidV7Ids::new(std::sync::Arc::new(clock.clone()));
        let a: ChangePackId = ids.next();
        clock.advance_millis(1);
        let b: ChangePackId = ids.next();
        assert!(a < b);
        assert_eq!(a.as_bytes()[6] >> 4, 7);
    }

    #[test]
    fn sequential_ids_are_deterministic() {
        let a = SequentialIds::new(1);
        let b = SequentialIds::new(1);
        let x: ChangePackId = a.next();
        let y: ChangePackId = b.next();
        assert_eq!(x, y);
        let z: ChangePackId = a.next();
        assert_ne!(x, z);
    }

    #[test]
    fn fixed_clock_advances() {
        let c = FixedClock::new(0);
        c.advance_millis(5);
        assert_eq!(c.now().unix_nanos(), 5_000_000);
    }
}
