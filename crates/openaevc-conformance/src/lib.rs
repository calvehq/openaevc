//! OpenAEVC conformance suite (spec/conformance.md): executable protocol law.
//!
//! Every normative MUST in `spec/` has a stable requirement ID mapped to one or more cases here.
//! Cases are written against the public client API only, so the same case runs against the
//! in-process reference runtime or any implementation exposing the v1 transport.
#![forbid(unsafe_code)]

pub mod cases;
pub mod ctx;
pub mod extension_target;
pub mod report;
pub mod target;

use std::future::Future;
use std::pin::Pin;
use std::time::Instant;

pub use ctx::Ctx;
pub use report::{CaseOutcome, Report, Status};
pub use target::{Client, Target};

/// Conformance suite version (independent of protocol and package versions).
pub const CONFORMANCE_VERSION: &str = "0.1.0";

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Profile {
    Core,
    Authority,
    Runtime,
    ExtensionHost,
    Full,
}

impl Profile {
    pub fn parse(s: &str) -> Option<Profile> {
        Some(match s.to_ascii_lowercase().replace('-', "_").as_str() {
            "core" => Profile::Core,
            "authority" => Profile::Authority,
            "runtime" => Profile::Runtime,
            "extension_host" => Profile::ExtensionHost,
            "full" => Profile::Full,
            _ => return None,
        })
    }

    /// Profiles whose cases run when this profile is selected. FULL includes everything.
    pub fn includes(&self, case: Profile) -> bool {
        *self == Profile::Full || *self == case
    }
}

pub type CaseResult = Result<(), String>;
pub type CaseFuture<'a> = Pin<Box<dyn Future<Output = CaseResult> + Send + 'a>>;

/// Why a case cannot run against a target (reported as skipped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skip(pub String);

pub struct Case {
    pub id: &'static str,
    pub profile: Profile,
    pub requirements: &'static [&'static str],
    pub run: for<'a> fn(&'a Ctx) -> CaseFuture<'a>,
}

impl std::fmt::Debug for Case {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Case")
            .field("id", &self.id)
            .field("profile", &self.profile)
            .finish()
    }
}

/// Runs every case of `profile` (optionally only IDs containing `filter`) against `target`.
pub async fn run(target: Target, profile: Profile, filter: Option<&str>) -> Report {
    let info = target.info().await.ok();
    let cx = Ctx::new(target);
    let mut outcomes = Vec::new();
    for case in cases::all() {
        if !profile.includes(case.profile) || filter.is_some_and(|f| !case.id.contains(f)) {
            continue;
        }
        let start = Instant::now();
        let status = match cx.skip_reason(&case) {
            Some(reason) => Status::Skipped(reason),
            None => match (case.run)(&cx).await {
                Ok(()) => Status::Passed,
                Err(e) if e.starts_with("SKIP: ") => Status::Skipped(e[6..].to_owned()),
                Err(e) => Status::Failed(e),
            },
        };
        outcomes.push(CaseOutcome {
            id: case.id.to_owned(),
            profile: case.profile,
            requirements: case.requirements.iter().map(|s| s.to_string()).collect(),
            status,
            duration_ms: start.elapsed().as_millis() as u64,
        });
    }
    Report::new(profile, cx.target.describe(), info, outcomes)
}
