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
    /// Should a new development-scope Finding fail this Target's Gate? Off by
    /// default — the point of Scope is that build-only debt stops blocking
    /// merges — but a Target that ships its build output can turn it on.
    #[serde(default)]
    pub gate_dev_scope: bool,
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
    /// The dependency is the attack, not a package with a bug in it. The fix is
    /// removal, never a version bump.
    Malicious,
}

/// What an Operator has decided about a license.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LicenseRule {
    /// Fine. Produces no Finding at all.
    Allowed,
    /// Not fine. Gates like any other new Finding.
    Denied,
    /// A human has to look. Does not Gate, and never auto-accepts.
    #[default]
    Review,
}

impl LicenseRule {
    pub fn as_str(self) -> &'static str {
        match self {
            LicenseRule::Allowed => "allowed",
            LicenseRule::Denied => "denied",
            LicenseRule::Review => "review",
        }
    }

    pub fn parse(s: &str) -> Option<LicenseRule> {
        match s {
            "allowed" | "allow" => Some(LicenseRule::Allowed),
            "denied" | "deny" => Some(LicenseRule::Denied),
            "review" => Some(LicenseRule::Review),
            _ => None,
        }
    }
}

/// Which licenses an Operator allows, denies, or wants to look at.
///
/// A license nobody has ruled on needs Review: HQ never decides a licensing
/// question on an Operator's behalf, and "unlisted" is not consent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LicensePolicy {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub review: Vec<String>,
}

impl LicensePolicy {
    pub fn rule_for(&self, license: &str) -> LicenseRule {
        let matches = |list: &[String]| list.iter().any(|l| l.eq_ignore_ascii_case(license));
        if matches(&self.deny) {
            LicenseRule::Denied
        } else if matches(&self.allow) {
            LicenseRule::Allowed
        } else {
            LicenseRule::Review
        }
    }

    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty() && self.review.is_empty()
    }
}

/// A leaked credential the Engine handed HQ so it can be checked against its
/// provider. Never persisted, never logged, never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct LeakedSecret(String);

impl LeakedSecret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The only way to read it. Callers must not copy it anywhere that lasts.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for LeakedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LeakedSecret(redacted)")
    }
}

/// Does a leaked credential still authenticate?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Validity {
    /// It still works. Not debt — an incident.
    Active,
    /// Nobody asked, or nobody could tell.
    #[default]
    Unverified,
    /// The provider no longer accepts it.
    Inactive,
}

impl Validity {
    pub fn as_str(self) -> &'static str {
        match self {
            Validity::Active => "active",
            Validity::Unverified => "unverified",
            Validity::Inactive => "inactive",
        }
    }

    pub fn parse(s: &str) -> Option<Validity> {
        match s {
            "active" => Some(Validity::Active),
            "unverified" => Some(Validity::Unverified),
            "inactive" => Some(Validity::Inactive),
            _ => None,
        }
    }

    /// Sorted first, so a live leaked key is the first thing anybody sees, and
    /// a dead one is the last.
    pub fn rank(self) -> u8 {
        match self {
            Validity::Active => 0,
            Validity::Unverified => 1,
            Validity::Inactive => 2,
        }
    }
}

/// How bad the problem is, as the Engine reports it.
///
/// Ordered worst-last so `max` picks the worst of several Engines' opinions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// The Engine said nothing, and nothing is not "low".
    #[default]
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Unknown => "unknown",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Engines spell severity every which way; this is the one place that knows.
    pub fn parse(s: &str) -> Option<Severity> {
        match s.trim().to_ascii_lowercase().as_str() {
            "critical" => Some(Severity::Critical),
            "high" | "error" => Some(Severity::High),
            "medium" | "moderate" | "warning" => Some(Severity::Medium),
            "low" | "info" | "note" | "negligible" => Some(Severity::Low),
            "unknown" | "none" | "" => Some(Severity::Unknown),
            _ => None,
        }
    }
}

/// Where a dependency is used. A CVE in a build-only package is real, but it is
/// not on the path an attacker can reach, so it must not block a merge the way a
/// runtime one does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// Shipped, reachable at run time.
    Runtime,
    /// Build, test, or tooling only.
    Development,
    /// Nobody could tell. Treated as Runtime — HQ does not de-noise on a guess.
    #[default]
    Unknown,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Runtime => "runtime",
            Scope::Development => "development",
            Scope::Unknown => "unknown",
        }
    }

    pub fn parse(s: &str) -> Option<Scope> {
        match s {
            "runtime" | "prod" | "production" => Some(Scope::Runtime),
            "development" | "dev" => Some(Scope::Development),
            "unknown" => Some(Scope::Unknown),
            _ => None,
        }
    }

    /// Does a Finding in this Scope block a merge?
    pub fn gates(self) -> bool {
        self != Scope::Development
    }
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
    /// Runtime or development dependency. Not part of the Fingerprint either: a
    /// package that moves from `devDependencies` to `dependencies` is the same
    /// Finding, it just starts blocking merges.
    #[serde(default)]
    pub scope: Scope,
    /// How bad the Engine that saw it says it is.
    #[serde(default)]
    pub severity: Severity,
    /// The credential itself, when the Engine found one and HQ is going to ask
    /// the provider about it. Skipped by serde on purpose: it must not reach
    /// the Store, a log, or a dump.
    #[serde(skip)]
    pub secret: Option<LeakedSecret>,
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
    /// The worst any Engine called it.
    #[serde(default)]
    pub severity: Severity,
    /// Published likelihood that this CVE is exploited in the next 30 days,
    /// 0.0–1.0. `None` for a problem that is not a CVE, or one nobody has
    /// scored.
    #[serde(default)]
    pub epss: Option<f64>,
    /// Where that score sits among all scored CVEs, 0.0–1.0.
    #[serde(default)]
    pub epss_percentile: Option<f64>,
    /// On CISA's Known Exploited Vulnerabilities list: not a prediction, a
    /// report that it has already been used.
    #[serde(default)]
    pub known_exploited: bool,
    /// For a secret: does the credential still authenticate? Only the verdict
    /// is kept — never the credential.
    #[serde(default)]
    pub validity: Validity,
}

impl Finding {
    /// The Scope HQ acts on. A Finding is development-scope only when every
    /// Engine that saw it said so — one Engine reporting runtime, or not
    /// reporting at all, makes it runtime.
    pub fn scope(&self) -> Scope {
        if self.observations.is_empty() {
            return Scope::Unknown;
        }
        if self
            .observations
            .iter()
            .all(|o| o.scope == Scope::Development)
        {
            Scope::Development
        } else if self.observations.iter().any(|o| o.scope == Scope::Runtime) {
            Scope::Runtime
        } else {
            Scope::Unknown
        }
    }

    /// Most urgent first. Something already being exploited outranks any
    /// prediction; after that it is severity, then the prediction, then the
    /// Fingerprint so the order never wobbles between runs.
    pub fn risk_key(&self) -> (u8, bool, Severity, u64, String) {
        (
            self.validity.rank(),
            self.known_exploited,
            self.severity,
            (self.epss.unwrap_or(0.0) * 1_000_000.0) as u64,
            self.fingerprint.display(),
        )
    }

    /// Does this Finding block a merge on its own?
    ///
    /// A live leaked credential does, Baseline or not — a key somebody can use
    /// right now is an incident, not debt HQ agreed to live with. So does a
    /// malicious dependency: nobody accepts malware as debt. A credential the
    /// provider has already stopped accepting does not.
    pub fn gates_regardless_of_baseline(&self) -> bool {
        self.kind == FindingKind::Malicious
            || (self.kind == FindingKind::Secret && self.validity == Validity::Active)
    }

    pub fn is_dead_secret(&self) -> bool {
        self.kind == FindingKind::Secret && self.validity == Validity::Inactive
    }

    /// One line an Operator or an agent can rank on.
    pub fn risk_summary(&self) -> String {
        let mut out = format!("severity={}", self.severity.as_str());
        if self.kind == FindingKind::Secret {
            out.push_str(&format!(" validity={}", self.validity.as_str()));
        }
        if let Some(epss) = self.epss {
            out.push_str(&format!(" epss={epss:.4}"));
        }
        if self.known_exploited {
            out.push_str(" known_exploited");
        }
        out
    }
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
