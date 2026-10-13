//! Conformance reports: human summary, JSON and JUnit XML.

use std::collections::BTreeSet;

use openaevc::protocol::{RuntimeInfo, PROTOCOL_VERSION};
use serde::Serialize;

use crate::{Profile, CONFORMANCE_VERSION};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "status",
    content = "detail",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
pub enum Status {
    Passed,
    Failed(String),
    Skipped(String),
    /// The target could not be driven through the case (e.g. a restart on a remote target without
    /// a lifecycle controller). Never counts as passed.
    NotExercised(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct CaseOutcome {
    pub id: String,
    pub profile: Profile,
    pub requirements: Vec<String>,
    pub status: Status,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub conformance_version: String,
    pub protocol_version: String,
    pub profile: Profile,
    pub target: String,
    pub implementation: Option<RuntimeInfo>,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub not_exercised: usize,
    pub requirements_passed: BTreeSet<String>,
    pub requirements_failed: BTreeSet<String>,
    pub requirements_skipped: BTreeSet<String>,
    pub requirements_not_exercised: BTreeSet<String>,
    pub cases: Vec<CaseOutcome>,
}

impl Report {
    pub fn new(
        profile: Profile,
        target: String,
        implementation: Option<RuntimeInfo>,
        cases: Vec<CaseOutcome>,
    ) -> Self {
        let mut r = Report {
            conformance_version: CONFORMANCE_VERSION.into(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            profile,
            target,
            implementation,
            passed: 0,
            failed: 0,
            skipped: 0,
            not_exercised: 0,
            requirements_passed: BTreeSet::new(),
            requirements_failed: BTreeSet::new(),
            requirements_skipped: BTreeSet::new(),
            requirements_not_exercised: BTreeSet::new(),
            cases,
        };
        for c in &r.cases {
            match c.status {
                Status::Passed => r.passed += 1,
                Status::Failed(_) => r.failed += 1,
                Status::Skipped(_) => r.skipped += 1,
                Status::NotExercised(_) => r.not_exercised += 1,
            }
        }
        for c in &r.cases {
            for req in &c.requirements {
                match c.status {
                    Status::Failed(_) => {
                        r.requirements_failed.insert(req.clone());
                    }
                    Status::Skipped(_) => {
                        r.requirements_skipped.insert(req.clone());
                    }
                    Status::NotExercised(_) => {
                        r.requirements_not_exercised.insert(req.clone());
                    }
                    Status::Passed => {
                        r.requirements_passed.insert(req.clone());
                    }
                }
            }
        }
        // A requirement passes only if every case covering it passed.
        let failed = r.requirements_failed.clone();
        let skipped = r.requirements_skipped.clone();
        let unexercised = r.requirements_not_exercised.clone();
        r.requirements_passed
            .retain(|x| !failed.contains(x) && !skipped.contains(x) && !unexercised.contains(x));
        r
    }

    /// Conformant only when every case of the profile passed (spec/conformance.md): a skipped or
    /// not-exercised case means the profile was not demonstrated.
    pub fn conformant(&self) -> bool {
        self.failed == 0 && self.skipped == 0 && self.not_exercised == 0 && !self.cases.is_empty()
    }

    pub fn summary(&self) -> String {
        let mut out = format!(
            "OpenAEVC conformance {} — protocol {} — profile {:?} — target {}\n",
            self.conformance_version, self.protocol_version, self.profile, self.target
        );
        if let Some(i) = &self.implementation {
            out.push_str(&format!(
                "implementation {} {}\n",
                i.implementation.name, i.implementation.version
            ));
        }
        for c in &self.cases {
            let (mark, detail) = match &c.status {
                Status::Passed => ("PASS", String::new()),
                Status::Failed(e) => ("FAIL", format!(" — {e}")),
                Status::Skipped(e) => ("SKIP", format!(" — {e}")),
                Status::NotExercised(e) => ("NOT_EXERCISED", format!(" — {e}")),
            };
            out.push_str(&format!(
                "{mark} {} [{}]{detail}\n",
                c.id,
                c.requirements.join(", ")
            ));
        }
        out.push_str(&format!(
            "\n{} passed, {} failed, {} skipped, {} not exercised; requirements: {} passed, {} failed, {} skipped, {} not exercised — {}\n",
            self.passed,
            self.failed,
            self.skipped,
            self.not_exercised,
            self.requirements_passed.len(),
            self.requirements_failed.len(),
            self.requirements_skipped.len(),
            self.requirements_not_exercised.len(),
            if self.conformant() { "CONFORMANT" } else { "NOT CONFORMANT" }
        ));
        out
    }

    pub fn json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    pub fn junit(&self) -> String {
        let esc = |s: &str| {
            s.replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;")
        };
        let mut out = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuite name=\"openaevc-conformance-{:?}\" tests=\"{}\" failures=\"{}\" skipped=\"{}\">\n",
            self.profile,
            self.cases.len(),
            self.failed,
            self.skipped + self.not_exercised
        );
        for c in &self.cases {
            out.push_str(&format!(
                "  <testcase classname=\"{:?}\" name=\"{}\" time=\"{:.3}\">\n    <properties><property name=\"requirements\" value=\"{}\"/></properties>\n",
                c.profile,
                esc(&c.id),
                c.duration_ms as f64 / 1000.0,
                esc(&c.requirements.join(","))
            ));
            match &c.status {
                Status::Failed(e) => {
                    out.push_str(&format!("    <failure message=\"{}\"/>\n", esc(e)))
                }
                Status::Skipped(e) => {
                    out.push_str(&format!("    <skipped message=\"{}\"/>\n", esc(e)))
                }
                Status::NotExercised(e) => out.push_str(&format!(
                    "    <skipped message=\"NOT_EXERCISED: {}\"/>\n",
                    esc(e)
                )),
                Status::Passed => {}
            }
            out.push_str("  </testcase>\n");
        }
        out.push_str("</testsuite>\n");
        out
    }
}
