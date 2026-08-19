use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetKind {
    Github,
    Image,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TargetId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Revision(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub id: TargetId,
    pub kind: TargetKind,
    pub default_revision: Revision,
    pub baseline_ready: bool,
    pub baseline: Vec<Fingerprint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Fingerprint {
    pub target: String,
    pub problem_id: String,
    pub location_key: String,
}

impl Fingerprint {
    pub fn new(
        target: impl Into<String>,
        problem_id: impl Into<String>,
        location_key: impl Into<String>,
    ) -> Self {
        Self {
            target: target.into(),
            problem_id: problem_id.into(),
            location_key: location_key.into(),
        }
    }

    pub fn display(&self) -> String {
        format!("{}|{}|{}", self.target, self.problem_id, self.location_key)
    }

    pub fn parse(s: &str) -> Option<Self> {
        let mut parts = s.splitn(3, '|');
        Some(Self {
            target: parts.next()?.to_string(),
            problem_id: parts.next()?.to_string(),
            location_key: parts.next()?.to_string(),
        })
    }
}

/// Location key for a dependency Finding: manifest path plus package name.
pub fn dependency_location(manifest: &str, package: &str) -> String {
    format!("{manifest}::{package}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingKind {
    Sca,
    Secret,
    Sast,
    Iac,
    License,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingState {
    Open,
    Fixed,
    Dismissed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub engine: String,
    pub problem_id: String,
    pub location_key: String,
    pub kind: FindingKind,
    pub package: Option<String>,
    pub manifest: Option<String>,
    pub fixed_version: Option<String>,
    pub message: String,
    /// Where in the file the Engine saw it. Deliberately not part of the
    /// Fingerprint (ADR 0007) — it only decides where an annotation lands.
    #[serde(default)]
    pub line: Option<u32>,
}

impl Observation {
    pub fn fingerprint(&self, target: &str) -> Fingerprint {
        Fingerprint::new(target, &self.problem_id, &self.location_key)
    }

    pub fn is_safe_pin(&self) -> bool {
        self.kind == FindingKind::Sca
            && self.fixed_version.is_some()
            && self.package.is_some()
            && self.manifest.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub fingerprint: Fingerprint,
    pub state: FindingState,
    pub kind: FindingKind,
    pub observations: Vec<Observation>,
    pub last_revision: Option<Revision>,
    pub package: Option<String>,
    pub manifest: Option<String>,
    pub fixed_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Remediation {
    pub target: String,
    pub manifest: String,
    pub package: String,
    pub fixed_version: String,
    pub finding_fingerprints: Vec<Fingerprint>,
    pub pr_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CheckRun {
    pub repo: String,
    pub pr: u64,
    /// The Revision the Check Run is attached to. GitHub keys Check Runs on the
    /// commit, not the PR.
    #[serde(default)]
    pub head_sha: String,
    pub conclusion: String,
    pub summary: String,
    pub annotations: Vec<Annotation>,
}

/// One Finding, placed in the diff where a Developer will see it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    pub fingerprint: String,
    pub message: String,
    /// File the annotation lands on, derived from the Finding's location key.
    #[serde(default)]
    pub path: String,
    #[serde(default = "one")]
    pub start_line: u32,
    #[serde(default = "one")]
    pub end_line: u32,
    /// `failure` for a Finding that blocks the merge, `warning` for known debt.
    #[serde(default)]
    pub level: String,
    #[serde(default)]
    pub title: String,
}

fn one() -> u32 {
    1
}

/// The file a Finding's location key points at. Dependency locations are
/// `manifest::package`; everything else is already a path.
pub fn annotation_path(location_key: &str) -> String {
    location_key
        .split_once("::")
        .map(|(manifest, _)| manifest)
        .unwrap_or(location_key)
        .to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenedPr {
    pub repo: String,
    pub number: u64,
    pub title: String,
    pub body: String,
    #[serde(default)]
    pub head: String,
    #[serde(default)]
    pub base: String,
    pub files: Vec<PrFile>,
}

/// What HQ asks GitHub to open. The branch is already pushed by the time this
/// reaches the backend; `files` is what it changed, for humans and for the fake
/// backend's record.
#[derive(Debug, Clone)]
pub struct PrRequest {
    pub repo: String,
    pub title: String,
    pub body: String,
    pub head: String,
    pub base: String,
    pub files: Vec<PrFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrFile {
    pub path: String,
    pub content: String,
}
