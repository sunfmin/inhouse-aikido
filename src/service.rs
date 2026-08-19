use crate::domain::PrRequest;
use crate::domain::{
    Annotation, CheckRun, Finding, FindingKind, FindingState, Fingerprint, Observation,
    Remediation, Revision, Scope, Severity, Target, TargetId, TargetKind, Validity,
};
use crate::engine::{Engine, FakeEngine};
use crate::github::Github;
use crate::intel::{CveIntel, IntelSource, NoIntel};
use crate::notify::{Notifier, Silent};
use crate::remediation::{Remediator, SyntheticRemediator, UnconfiguredRemediator};
use crate::store::Store;
use crate::verify::{NoVerification, SecretVerifier};
use crate::workspace::{Checkout, GitCheckout, Workspace};

/// What one Scan saw. Engines that failed are named, so a Gate can fail closed
/// instead of treating silence as cleanliness.
#[derive(Debug, Clone)]
pub struct ScanOutcome {
    pub revision: Revision,
    pub observations: Vec<Observation>,
    pub failed_engines: Vec<String>,
    /// What the public sources say about the CVEs this Scan saw. Fetched in the
    /// slow half, so the write path does no network I/O.
    pub intel: std::collections::HashMap<String, CveIntel>,
    /// Whether each leaked credential still authenticates, keyed by Fingerprint.
    /// The verdict travels; the credential does not.
    pub validity: std::collections::HashMap<String, Validity>,
}

pub struct Hq {
    pub store: Store,
    /// Chosen when HQ is constructed, never loaded from the Store's state.
    pub github: Box<dyn Github>,
    /// How a Revision gets onto disk when nobody hands HQ a workspace.
    pub checkout: Box<dyn Checkout>,
    /// How a pin becomes a branch a Developer can merge.
    pub remediator: Box<dyn Remediator>,
    /// Where exploitability intel comes from. `NoIntel` by default: HQ makes no
    /// outbound call nobody asked for.
    pub intel: Box<dyn IntelSource>,
    /// How long cached intel is trusted before it is fetched again.
    pub intel_ttl: std::time::Duration,
    /// Whether a leaked credential still authenticates. Off by default: HQ does
    /// not hand a Target's secrets to a third party unasked.
    pub verifier: Box<dyn SecretVerifier>,
    /// Where a digest goes when a Scan of a default Revision opens Findings.
    pub notifier: Box<dyn Notifier>,
}

/// One message, most urgent first, with the Fingerprint to act on.
fn digest(target: &str, findings: &[&Finding]) -> String {
    let mut out = format!(
        "*{target}* — {} new Finding{} on the default Revision",
        findings.len(),
        if findings.len() == 1 { "" } else { "s" }
    );
    for f in findings {
        out.push_str(&format!(
            "\n• {:?} `{}` — {} — `{}`",
            f.kind,
            f.fingerprint.problem_id,
            f.risk_summary(),
            f.fingerprint.display()
        ));
    }
    out
}

/// What a Developer reads first on the PR: how bad it is, whether anyone is
/// already exploiting it, and whether it is blocking their merge.
fn annotation_title(f: &Finding, gates: bool) -> String {
    let mut title = format!(
        "{:?} {} severity={}",
        f.kind,
        f.fingerprint.problem_id,
        f.severity.as_str()
    );
    if f.known_exploited {
        title.push_str(" known-exploited");
    }
    if f.kind == FindingKind::Secret && f.validity != Validity::Unverified {
        title.push_str(&format!(" credential={}", f.validity.as_str()));
    }
    if !gates {
        title.push_str(&format!(" ({} dependency)", f.scope().as_str()));
    }
    title
}

/// What an Operator or an agent asked to see. Grouped rather than passed as a
/// row of options nobody can read at the call site.
#[derive(Debug, Default, Clone, Copy)]
pub struct FindingFilter<'a> {
    pub target: Option<&'a str>,
    pub state: Option<&'a str>,
    pub kind: Option<&'a str>,
    pub scope: Option<&'a str>,
    /// Hide anything the Engines called less bad than this.
    pub min_severity: Option<Severity>,
    /// Only what CISA says is already being exploited.
    pub known_exploited: bool,
    /// Only credentials with this verdict.
    pub validity: Option<Validity>,
}

/// How long HQ trusts a cached EPSS score or KEV entry. A day: the feeds are
/// published daily, and a Scan must not spend its time refetching them.
fn default_intel_ttl() -> std::time::Duration {
    let hours = std::env::var("HQ_INTEL_TTL_HOURS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(24);
    std::time::Duration::from_secs(hours * 3600)
}

impl Hq {
    /// Open HQ on the fake GitHub backend — the default for tests and local
    /// development. Its checks and PRs are restored from the previous invocation.
    pub fn open(url: &str, schema: &str) -> Result<Self, String> {
        let store = Store::open(url, schema)?;
        let github = Box::new(store.load_fake_github()?);
        Ok(Self {
            store,
            github,
            checkout: Box::new(GitCheckout::default()),
            remediator: Box::new(SyntheticRemediator),
            intel: Box::new(NoIntel),
            intel_ttl: default_intel_ttl(),
            verifier: Box::new(NoVerification),
            // Configured by the caller; a Scan run from a library never posts
            // anywhere by accident.
            notifier: Box::new(Silent),
        })
    }

    /// Open HQ on a caller-chosen GitHub backend.
    pub fn open_with_github(
        url: &str,
        schema: &str,
        github: Box<dyn Github>,
    ) -> Result<Self, String> {
        Ok(Self {
            store: Store::open(url, schema)?,
            github,
            checkout: Box::new(GitCheckout::default()),
            // A caller choosing their own backend must choose how pins are
            // prepared too; the synthetic one would push nothing.
            remediator: Box::new(UnconfiguredRemediator),
            intel: Box::new(NoIntel),
            intel_ttl: default_intel_ttl(),
            verifier: Box::new(NoVerification),
            // Configured by the caller; a Scan run from a library never posts
            // anywhere by accident.
            notifier: Box::new(Silent),
        })
    }

    /// Use a different way of getting a Revision onto disk.
    pub fn with_checkout(mut self, checkout: Box<dyn Checkout>) -> Self {
        self.checkout = checkout;
        self
    }

    /// Use a different way of preparing a pin.
    pub fn with_remediator(mut self, remediator: Box<dyn Remediator>) -> Self {
        self.remediator = remediator;
        self
    }

    pub fn with_intel(mut self, intel: Box<dyn IntelSource>) -> Self {
        self.intel = intel;
        self
    }

    pub fn with_verifier(mut self, verifier: Box<dyn SecretVerifier>) -> Self {
        self.verifier = verifier;
        self
    }

    pub fn with_notifier(mut self, notifier: Box<dyn Notifier>) -> Self {
        self.notifier = notifier;
        self
    }

    pub fn save(&self) -> Result<(), String> {
        self.store.save(self.github.as_ref())
    }

    pub fn enroll(
        &mut self,
        kind: TargetKind,
        name: &str,
        revision: &str,
    ) -> Result<String, String> {
        if self.store.state.targets.contains_key(name) {
            return Ok(format!("already enrolled {name}"));
        }
        self.store.state.targets.insert(
            name.to_string(),
            Target {
                id: TargetId(name.to_string()),
                kind,
                default_revision: Revision(revision.to_string()),
                baseline_ready: false,
                baseline: vec![],
                gate_dev_scope: false,
            },
        );
        Ok(format!(
            "enrolled {name} ({kind:?}) default_revision={revision}"
        ))
    }

    pub fn unenroll(&mut self, name: &str) -> Result<String, String> {
        self.store
            .state
            .targets
            .remove(name)
            .ok_or_else(|| format!("not enrolled: {name}"))?;
        Ok(format!("unenrolled {name}"))
    }

    /// Is this repo a Target at all? Enrollment is opt-in, so most repos are not.
    /// What this Target's Gate blocks on. Passing nothing just reports it.
    pub fn set_policy(
        &mut self,
        name: &str,
        gate_dev_scope: Option<bool>,
    ) -> Result<String, String> {
        let target = self
            .store
            .state
            .targets
            .get_mut(name)
            .ok_or_else(|| format!("not enrolled: {name}"))?;
        if let Some(value) = gate_dev_scope {
            target.gate_dev_scope = value;
        }
        Ok(format!("{name} gate_dev_scope={}", target.gate_dev_scope))
    }

    pub fn tracks(&self, name: &str) -> bool {
        self.store.state.targets.contains_key(name)
    }

    /// Has the Target's first default-Revision Scan written the Baseline? The
    /// Gate starts only after that.
    pub fn baseline_ready(&self, name: &str) -> bool {
        self.store
            .state
            .targets
            .get(name)
            .is_some_and(|t| t.baseline_ready)
    }

    pub fn list_targets(&self) -> String {
        if self.store.state.targets.is_empty() {
            return "no targets".into();
        }
        let mut lines: Vec<String> = self
            .store
            .state
            .targets
            .values()
            .map(|t| {
                format!(
                    "{} kind={:?} default={} baseline_ready={} gate_dev_scope={}",
                    t.id.0, t.kind, t.default_revision.0, t.baseline_ready, t.gate_dev_scope
                )
            })
            .collect();
        lines.sort();
        lines.join("\n")
    }

    pub fn add_fake_obs(&mut self, target: &str, revision: &str, obs: Observation) {
        let key = FakeEngine::key(target, revision);
        self.store
            .state
            .fake
            .observations
            .entry(key)
            .or_default()
            .push(obs);
    }

    pub fn add_fake_fail(&mut self, target: &str, revision: &str) {
        self.store
            .state
            .fake
            .fail
            .push(FakeEngine::key(target, revision));
    }

    pub fn scan(&mut self, name: &str, revision: Option<&str>) -> Result<String, String> {
        self.scan_named(name, revision, &["fake"], None, false)
    }

    pub fn scan_named(
        &mut self,
        name: &str,
        revision: Option<&str>,
        names: &[&str],
        workspace: Option<&std::path::Path>,
        is_pr: bool,
    ) -> Result<String, String> {
        let engines = self.select_engines(names);
        self.scan_with(name, revision, &engines, workspace, is_pr)
    }

    pub fn select_engines(&self, names: &[&str]) -> Vec<Box<dyn Engine>> {
        let mut out: Vec<Box<dyn Engine>> = Vec::new();
        for name in names {
            match *name {
                "fake" => out.push(Box::new(self.store.fake_engine("fake"))),
                "gitleaks" => out.push(Box::new(crate::engines::gitleaks::GitleaksEngine)),
                "trivy" => out.push(Box::new(crate::engines::trivy::TrivyEngine)),
                "opengrep" => out.push(Box::new(crate::engines::opengrep::OpengrepEngine)),
                _ => {}
            }
        }
        if out.is_empty() {
            out.push(Box::new(self.store.fake_engine("fake")));
        }
        out
    }

    pub fn scan_with(
        &mut self,
        name: &str,
        revision: Option<&str>,
        engines: &[Box<dyn Engine>],
        workspace: Option<&std::path::Path>,
        is_pr: bool,
    ) -> Result<String, String> {
        let outcome = self.observe(name, revision, engines, workspace)?;
        if !outcome.failed_engines.is_empty() {
            return Err(format!(
                "engines failed: {}",
                outcome.failed_engines.join(",")
            ));
        }
        self.record(name, revision, &outcome, is_pr)
    }

    /// Run Engines against a Revision and report what they saw.
    ///
    /// This is the slow half of a Scan — a clone and one subprocess per Engine —
    /// and it writes nothing, so a queue worker can do it off HQ's write path.
    pub fn observe(
        &mut self,
        name: &str,
        revision: Option<&str>,
        engines: &[Box<dyn Engine>],
        workspace: Option<&std::path::Path>,
    ) -> Result<ScanOutcome, String> {
        let target = self
            .store
            .state
            .targets
            .get(name)
            .cloned()
            .ok_or_else(|| format!("not enrolled: {name}"))?;
        let rev = Revision(
            revision
                .unwrap_or(target.default_revision.0.as_str())
                .to_string(),
        );
        // Nobody handed HQ a checkout, and an Engine wants to read files: clone
        // the Revision ourselves. The workspace goes away when `cloned` drops,
        // including if an Engine fails.
        let mut cloned: Option<Workspace> = None;
        if workspace.is_none()
            && target.kind == TargetKind::Github
            && engines.iter().any(|e| e.needs_workspace())
        {
            cloned = Some(self.checkout.checkout(name, &rev.0)?);
        }
        let workspace = workspace.or_else(|| cloned.as_ref().map(|w| w.path()));

        let mut observations = Vec::new();
        let mut failed = Vec::new();
        for engine in engines {
            match engine.scan(&target, &rev, workspace) {
                Ok(mut obs) => observations.append(&mut obs),
                // A timeout is a failed Engine like any other: the Gate must
                // fail closed rather than call a hung scanner clean.
                Err(e) => failed.push(e.engine()),
            }
        }
        // Engines report a vulnerable package; the Target's manifests say
        // whether it is shipped. Read them while the workspace is still here.
        crate::scope::enrich(workspace, &mut observations);
        let intel = self.lookup_intel(&observations);
        let validity = self.verify_secrets(name, &observations);
        // The credentials leave with the Observations they came in on. Nothing
        // downstream of here has ever seen one.
        for obs in observations.iter_mut() {
            obs.secret = None;
        }
        Ok(ScanOutcome {
            revision: rev,
            observations,
            failed_engines: failed,
            intel,
            validity,
        })
    }

    /// Fold what a Scan saw into HQ's Findings. The fast half, and the only half
    /// that writes.
    pub fn record(
        &mut self,
        name: &str,
        revision: Option<&str>,
        outcome: &ScanOutcome,
        is_pr: bool,
    ) -> Result<String, String> {
        let target = self
            .store
            .state
            .targets
            .get(name)
            .cloned()
            .ok_or_else(|| format!("not enrolled: {name}"))?;
        let rev = Revision(
            revision
                .unwrap_or(target.default_revision.0.as_str())
                .to_string(),
        );
        let observations = &outcome.observations;
        let was_baseline = target.baseline_ready;
        self.apply_observations(name, &rev, observations, is_pr);
        self.rank_findings(name, &outcome.intel, &outcome.validity);
        let mut msg = format!(
            "scanned {name}@{} observations={}",
            rev.0,
            observations.len()
        );
        let target = self.store.state.targets.get(name).unwrap();
        if target.baseline_ready && !was_baseline {
            msg.push_str(" baseline_written");
        }
        if !is_pr && was_baseline && rev.0 == target.default_revision.0 {
            let (opened, unpinnable) = self.maybe_remediate(name)?;
            if opened > 0 {
                msg.push_str(&format!(" remediations={opened}"));
            }
            if !unpinnable.is_empty() {
                // Say so out loud. A Finding HQ silently declined to fix reads
                // as a Finding nobody has to think about.
                msg.push_str(&format!(" unpinnable={}", unpinnable.join(",")));
            }
        }
        // Every Scan of a default Revision keeps the ledger current, Baseline
        // day included — otherwise turning the digest on years later would
        // announce a Target's whole history at once.
        if !is_pr && rev.0 == self.store.state.targets[name].default_revision.0 {
            if let Some(announced) = self.account_for_findings(name, was_baseline)? {
                msg.push_str(&format!(" announced={announced}"));
            }
        }
        Ok(msg)
    }

    /// Ask the intel source about the CVEs in this Scan, using the cache first.
    ///
    /// Never fails the Scan: a source that is down, or turned off, leaves the
    /// Findings ranked by Engine severity, which is where they started.
    fn lookup_intel(
        &mut self,
        observations: &[Observation],
    ) -> std::collections::HashMap<String, CveIntel> {
        let wanted = crate::intel::cve_ids(observations.iter().map(|o| o.problem_id.clone()));
        if wanted.is_empty() {
            return std::collections::HashMap::new();
        }
        let mut known = self
            .store
            .cached_intel(&wanted, self.intel_ttl)
            .unwrap_or_default();
        let missing: Vec<String> = wanted
            .into_iter()
            .filter(|cve| !known.contains_key(cve))
            .collect();
        if missing.is_empty() || !self.intel.answers() {
            return known;
        }
        match self.intel.fetch(&missing) {
            Ok(fetched) => {
                // Cache what the source did not know about too. A CVE nobody
                // has scored is an answer, and refetching it every Scan is not
                // a better one.
                let answered: std::collections::HashMap<String, CveIntel> = missing
                    .into_iter()
                    .map(|cve| {
                        let data = fetched.get(&cve).copied().unwrap_or_default();
                        (cve, data)
                    })
                    .collect();
                let _ = self.store.cache_intel(&answered);
                known.extend(answered);
            }
            Err(e) => eprintln!("hq: intel unavailable, ranking on engine severity only: {e}"),
        }
        known
    }

    /// Tell somebody about Findings that opened on a default Revision.
    ///
    /// Nobody opens a pull request for a CVE published overnight, so without
    /// this the Gate never sees it and nobody is looking. One digest per Scan,
    /// never one message per Finding, and never the same Finding twice.
    fn account_for_findings(
        &mut self,
        target: &str,
        was_baseline: bool,
    ) -> Result<Option<usize>, String> {
        let open: Vec<&Finding> = self
            .store
            .state
            .findings
            .values()
            .filter(|f| f.fingerprint.target == target)
            .filter(|f| f.state == FindingState::Open)
            .collect();
        if open.is_empty() {
            return Ok(None);
        }
        let keys: Vec<String> = open.iter().map(|f| f.fingerprint.display()).collect();
        let seen = self.store.already_announced(&keys)?;
        let mut fresh: Vec<&Finding> = open
            .into_iter()
            .filter(|f| !seen.contains(&f.fingerprint.display()))
            .collect();
        if fresh.is_empty() {
            return Ok(None);
        }
        // Nothing to say, or nobody to say it to: the Findings are still
        // accounted for, so they are not announced as news later.
        if !self.notifier.enabled() || !was_baseline {
            let all: Vec<String> = fresh.iter().map(|f| f.fingerprint.display()).collect();
            self.store.remember_announced(&all)?;
            return Ok(None);
        }
        fresh.sort_by(|a, b| {
            let (a, b) = (a.risk_key(), b.risk_key());
            a.0.cmp(&b.0)
                .then(b.1.cmp(&a.1))
                .then(b.2.cmp(&a.2))
                .then(b.3.cmp(&a.3))
                .then(a.4.cmp(&b.4))
        });
        let message = digest(target, &fresh);
        let announced: Vec<String> = fresh.iter().map(|f| f.fingerprint.display()).collect();
        // A notifier that is down must not fail the Scan, and must not mark
        // anything announced — the next Scan says it instead.
        match self.notifier.post(&message) {
            Ok(()) => {
                self.store.remember_announced(&announced)?;
                Ok(Some(announced.len()))
            }
            Err(e) => {
                eprintln!("hq: could not post the digest, will try again next Scan: {e}");
                Ok(None)
            }
        }
    }

    /// Ask each leaked credential's provider whether it still works.
    ///
    /// Only the verdict comes back. A provider HQ cannot reach leaves the
    /// Finding Unverified — never Inactive, because calling a live key dead is
    /// the one wrong answer that lets a real incident through.
    fn verify_secrets(
        &self,
        target: &str,
        observations: &[Observation],
    ) -> std::collections::HashMap<String, Validity> {
        let mut out = std::collections::HashMap::new();
        if !self.verifier.enabled() {
            return out;
        }
        for obs in observations {
            let Some(secret) = obs.secret.as_ref() else {
                continue;
            };
            let verdict = self.verifier.check(&obs.problem_id, secret.expose());
            out.insert(obs.fingerprint(target).display(), verdict);
        }
        out
    }

    /// Give every Finding of this Target the severity its Engines reported and
    /// the intel its CVE carries.
    fn rank_findings(
        &mut self,
        target: &str,
        intel: &std::collections::HashMap<String, CveIntel>,
        validity: &std::collections::HashMap<String, Validity>,
    ) {
        for finding in self.store.state.findings.values_mut() {
            if finding.fingerprint.target != target {
                continue;
            }
            if let Some(verdict) = validity.get(&finding.fingerprint.display()) {
                finding.validity = *verdict;
            }
            finding.severity = finding
                .observations
                .iter()
                .map(|o| o.severity)
                .max()
                .unwrap_or_default();
            if let Some(data) = intel.get(&finding.fingerprint.problem_id) {
                finding.epss = data.epss;
                finding.epss_percentile = data.percentile;
                finding.known_exploited = data.known_exploited;
            }
        }
    }

    fn apply_observations(
        &mut self,
        target: &str,
        rev: &Revision,
        observations: &[Observation],
        is_pr: bool,
    ) {
        let fps: Vec<Fingerprint> = observations.iter().map(|o| o.fingerprint(target)).collect();

        for obs in observations {
            let fp = obs.fingerprint(target);
            let key = fp.display();
            let finding = self
                .store
                .state
                .findings
                .entry(key)
                .or_insert_with(|| Finding {
                    fingerprint: fp.clone(),
                    state: FindingState::Open,
                    kind: obs.kind,
                    observations: vec![],
                    last_revision: None,
                    package: obs.package.clone(),
                    manifest: obs.manifest.clone(),
                    fixed_version: obs.fixed_version.clone(),
                    severity: Severity::Unknown,
                    epss: None,
                    epss_percentile: None,
                    known_exploited: false,
                    validity: Validity::Unverified,
                });
            finding.kind = obs.kind;
            finding.last_revision = Some(rev.clone());
            if finding.state != FindingState::Dismissed {
                finding.state = FindingState::Open;
            }
            finding.observations.retain(|o| o.engine != obs.engine);
            finding.observations.push(obs.clone());
            if obs.fixed_version.is_some() {
                finding.fixed_version = obs.fixed_version.clone();
            }
            if obs.package.is_some() {
                finding.package = obs.package.clone();
            }
            if obs.manifest.is_some() {
                finding.manifest = obs.manifest.clone();
            }
        }

        if !is_pr {
            let keys: Vec<String> = self.store.state.findings.keys().cloned().collect();
            for key in keys {
                let f = self.store.state.findings.get_mut(&key).unwrap();
                if f.fingerprint.target != target {
                    continue;
                }
                if f.state == FindingState::Dismissed {
                    continue;
                }
                if !fps.iter().any(|p| p.display() == key) {
                    f.state = FindingState::Fixed;
                    f.observations.clear();
                }
            }

            let t = self.store.state.targets.get_mut(target).unwrap();
            if !t.baseline_ready && rev.0 == t.default_revision.0 {
                t.baseline = self
                    .store
                    .state
                    .findings
                    .values()
                    .filter(|f| f.fingerprint.target == target && f.state != FindingState::Fixed)
                    .map(|f| f.fingerprint.clone())
                    .collect();
                t.baseline_ready = true;
            }
        }
    }

    /// Returns how many Remediations were opened, and the manifests HQ has no
    /// way to pin.
    fn maybe_remediate(&mut self, target: &str) -> Result<(usize, Vec<String>), String> {
        // A backend that cannot open a PR opens none, rather than recording a
        // Remediation nobody can merge.
        if !self.github.can_open_pr() {
            return Ok((0, vec![]));
        }
        let t = self.store.state.targets.get(target).unwrap();
        if !t.baseline_ready {
            return Ok((0, vec![]));
        }
        if t.kind != TargetKind::Github {
            return Ok((0, vec![]));
        }
        // Group safe pin Findings by (manifest, package, fixed_version)
        let mut groups: std::collections::HashMap<(String, String, String), Vec<Fingerprint>> =
            std::collections::HashMap::new();
        let baseline = t.baseline.clone();
        for f in self.store.state.findings.values() {
            if f.fingerprint.target != target {
                continue;
            }
            if f.state != FindingState::Open {
                continue;
            }
            if f.kind != FindingKind::Sca {
                continue;
            }
            if baseline.iter().any(|b| b == &f.fingerprint) {
                continue;
            }
            let (Some(manifest), Some(package), Some(fixed)) =
                (&f.manifest, &f.package, &f.fixed_version)
            else {
                continue;
            };
            groups
                .entry((manifest.clone(), package.clone(), fixed.clone()))
                .or_default()
                .push(f.fingerprint.clone());
        }

        let default_rev = t.default_revision.0.clone();
        let mut opened = 0;
        let mut gated: Vec<(u64, Vec<Fingerprint>)> = Vec::new();
        let existing: Vec<(String, String, String)> = self
            .store
            .state
            .remediations
            .iter()
            .filter(|r| r.target == target)
            .map(|r| {
                (
                    r.manifest.clone(),
                    r.package.clone(),
                    r.fixed_version.clone(),
                )
            })
            .collect();

        // Deterministic order, so a Target with several pins opens its PRs the
        // same way every run.
        let mut groups: Vec<_> = groups.into_iter().collect();
        groups.sort_by(|a, b| a.0.cmp(&b.0));

        let mut skipped: Vec<String> = Vec::new();
        for ((manifest, package, fixed), fps) in groups {
            if existing
                .iter()
                .any(|(m, p, v)| m == &manifest && p == &package && v == &fixed)
            {
                continue;
            }
            let prepared =
                match self
                    .remediator
                    .prepare(target, &default_rev, &manifest, &package, &fixed)
                {
                    Ok(Some(prepared)) => prepared,
                    // An ecosystem HQ cannot pin gets no Remediation. A placeholder
                    // edit that looks like a fix is worse than none.
                    Ok(None) => {
                        skipped.push(manifest.clone());
                        continue;
                    }
                    Err(e) => return Err(format!("cannot prepare a pin for {package}: {e}")),
                };
            let title = format!("Remediation: pin {package} to {fixed} in {manifest}");
            let body = format!(
                "Safe pin-bump for {}.\n\nFindings:\n{}",
                target,
                fps.iter()
                    .map(|f| format!("- {}", f.display()))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
            let pr = self.github.open_pr(PrRequest {
                repo: target.to_string(),
                title,
                body,
                head: prepared.branch,
                base: default_rev.clone(),
                files: prepared.files,
            })?;
            self.store.state.remediations.push(Remediation {
                target: target.to_string(),
                manifest,
                package,
                fixed_version: fixed,
                finding_fingerprints: fps.clone(),
                pr_number: pr,
            });
            gated.push((pr, fps));
            opened += 1;
        }
        for (pr, fps) in gated {
            self.post_gate(target, pr, &default_rev, false, &fps)?;
        }
        skipped.sort();
        skipped.dedup();
        Ok((opened, skipped))
    }

    fn filtered_findings(&self, filter: &FindingFilter) -> Vec<&Finding> {
        let FindingFilter {
            target,
            state,
            kind,
            scope,
            min_severity,
            known_exploited: known_exploited_only,
            validity,
        } = *filter;
        let mut items: Vec<&Finding> = self
            .store
            .state
            .findings
            .values()
            .filter(|f| target.is_none_or(|t| f.fingerprint.target == t))
            .filter(|f| {
                state.is_none_or(|s| match s {
                    "open" => f.state == FindingState::Open,
                    "fixed" => f.state == FindingState::Fixed,
                    "dismissed" => f.state == FindingState::Dismissed,
                    _ => true,
                })
            })
            .filter(|f| {
                kind.is_none_or(|k| match k {
                    "sca" => f.kind == FindingKind::Sca,
                    "secret" => f.kind == FindingKind::Secret,
                    "sast" => f.kind == FindingKind::Sast,
                    "iac" => f.kind == FindingKind::Iac,
                    "license" => f.kind == FindingKind::License,
                    _ => true,
                })
            })
            .filter(|f| scope.is_none_or(|s| Scope::parse(s) == Some(f.scope())))
            .filter(|f| min_severity.is_none_or(|m| f.severity >= m))
            .filter(|f| !known_exploited_only || f.known_exploited)
            .filter(|f| validity.is_none_or(|v| f.validity == v))
            .collect();
        // Most urgent first: already exploited, then severity, then the
        // prediction, then the Fingerprint so the order never wobbles.
        items.sort_by(|a, b| {
            let (a, b) = (a.risk_key(), b.risk_key());
            a.0.cmp(&b.0)
                .then(b.1.cmp(&a.1))
                .then(b.2.cmp(&a.2))
                .then(b.3.cmp(&a.3))
                .then(a.4.cmp(&b.4))
        });
        items
    }

    pub fn findings_text(&self, filter: &FindingFilter) -> String {
        let items = self.filtered_findings(filter);
        if items.is_empty() {
            return "no findings".into();
        }
        items
            .iter()
            .map(|f| {
                let engines: Vec<&str> = f.observations.iter().map(|o| o.engine.as_str()).collect();
                format!(
                    "{} state={:?} kind={:?} scope={} {} engines={}",
                    f.fingerprint.display(),
                    f.state,
                    f.kind,
                    f.scope().as_str(),
                    f.risk_summary(),
                    engines.join(",")
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn findings_json(&self, filter: &FindingFilter) -> Result<String, String> {
        let views: Vec<crate::brief::FindingView> = self
            .filtered_findings(filter)
            .into_iter()
            .map(crate::brief::FindingView::from_finding)
            .collect();
        serde_json::to_string_pretty(&views).map_err(|e| e.to_string())
    }

    pub fn show(&self, fp: &Fingerprint) -> Result<String, String> {
        let f = self
            .store
            .state
            .finding(fp)
            .ok_or_else(|| format!("unknown finding {}", fp.display()))?;
        serde_json::to_string_pretty(&crate::brief::FindingView::from_finding(f))
            .map_err(|e| e.to_string())
    }

    pub fn brief(&self, fp: Option<&Fingerprint>) -> Result<String, String> {
        let f = if let Some(fp) = fp {
            self.store
                .state
                .finding(fp)
                .ok_or_else(|| format!("unknown finding {}", fp.display()))?
        } else {
            self.next_agent_finding()
                .ok_or_else(|| "no agent-fixable Open Finding".to_string())?
        };
        Ok(crate::brief::brief_markdown(f))
    }

    fn next_agent_finding(&self) -> Option<&Finding> {
        let mut items: Vec<&Finding> = self
            .store
            .state
            .findings
            .values()
            .filter(|f| crate::brief::is_agent_fixable(f))
            .collect();
        // Most urgent first, and only then the kind order — a CVE somebody is
        // already exploiting outranks a secret nobody has touched, but within
        // one severity a leaked credential is still the first thing to fix.
        items.sort_by(|a, b| {
            a.validity
                .rank()
                .cmp(&b.validity.rank())
                .then(b.known_exploited.cmp(&a.known_exploited))
                .then(b.severity.cmp(&a.severity))
                .then(crate::brief::pickup_rank(a).cmp(&crate::brief::pickup_rank(b)))
                .then(b.epss.unwrap_or(0.0).total_cmp(&a.epss.unwrap_or(0.0)))
                .then(a.fingerprint.display().cmp(&b.fingerprint.display()))
        });
        items.into_iter().next()
    }

    pub fn dismissed_text(&self) -> String {
        let mut items: Vec<&Finding> = self
            .store
            .state
            .findings
            .values()
            .filter(|f| f.state == FindingState::Dismissed)
            .collect();
        items.sort_by_key(|f| f.fingerprint.display());
        if items.is_empty() {
            return "no dismissed findings".into();
        }
        items
            .iter()
            .map(|f| f.fingerprint.display())
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn dismiss(&mut self, fp: &Fingerprint) -> Result<String, String> {
        let f = self
            .store
            .state
            .finding_mut(fp)
            .ok_or_else(|| format!("unknown finding {}", fp.display()))?;
        f.state = FindingState::Dismissed;
        Ok(format!("dismissed {}", fp.display()))
    }

    pub fn reopen(&mut self, fp: &Fingerprint) -> Result<String, String> {
        let f = self
            .store
            .state
            .finding_mut(fp)
            .ok_or_else(|| format!("unknown finding {}", fp.display()))?;
        if f.state != FindingState::Dismissed {
            return Err(format!("not dismissed: {}", fp.display()));
        }
        f.state = if f.observations.is_empty() {
            FindingState::Fixed
        } else {
            FindingState::Open
        };
        Ok(format!("reopened {} state={:?}", fp.display(), f.state))
    }

    pub fn handle_pr(
        &mut self,
        repo: &str,
        pr: u64,
        head: &str,
        _base: &str,
    ) -> Result<String, String> {
        self.handle_pr_named(repo, pr, head, _base, &["fake"], None)
    }

    pub fn handle_pr_named(
        &mut self,
        repo: &str,
        pr: u64,
        head: &str,
        _base: &str,
        names: &[&str],
        workspace: Option<&std::path::Path>,
    ) -> Result<String, String> {
        if !self.store.state.targets.contains_key(repo) {
            return Err(format!("not enrolled: {repo}"));
        }
        let engines = self.select_engines(names);
        if !self.store.state.targets[repo].baseline_ready {
            return Err("baseline not ready".into());
        }
        match self.scan_with(repo, Some(head), &engines, workspace, true) {
            Ok(_) => self.post_gate(repo, pr, head, false, &[]),
            Err(e) if e.starts_with("engines failed") => self.post_gate(repo, pr, head, true, &[]),
            Err(e) => Err(e),
        }
    }

    /// Post the Gate for a Scan somebody else already ran — the queue worker
    /// path, where `observe` happened on a worker thread and only the folding-in
    /// happens here, under HQ's write lock.
    pub fn record_gate(
        &mut self,
        repo: &str,
        pr: u64,
        head: &str,
        outcome: &ScanOutcome,
    ) -> Result<String, String> {
        if !self.store.state.targets.contains_key(repo) {
            return Err(format!("not enrolled: {repo}"));
        }
        if !self.store.state.targets[repo].baseline_ready {
            return Err("baseline not ready".into());
        }
        if !outcome.failed_engines.is_empty() {
            return self.post_gate(repo, pr, head, true, &[]);
        }
        self.record(repo, Some(head), outcome, true)?;
        self.post_gate(repo, pr, head, false, &[])
    }

    fn post_gate(
        &mut self,
        repo: &str,
        pr: u64,
        head: &str,
        engine_failed: bool,
        ignore: &[Fingerprint],
    ) -> Result<String, String> {
        if engine_failed {
            let check = CheckRun {
                repo: repo.to_string(),
                pr,
                head_sha: head.to_string(),
                conclusion: "failure".into(),
                summary: "engines failed".into(),
                annotations: vec![],
            };
            self.github.upsert_check(check)?;
            return Ok(format!("gate=failure reason=engines_failed pr={pr}"));
        }
        let target = self
            .store
            .state
            .targets
            .get(repo)
            .ok_or_else(|| format!("not enrolled: {repo}"))?;
        let baseline = &target.baseline;
        let gate_dev_scope = target.gate_dev_scope;
        let head_rev = Revision(head.to_string());
        let mut new_open = Vec::new();
        let mut annotations = Vec::new();
        for f in self.store.state.findings.values() {
            if f.fingerprint.target != repo {
                continue;
            }
            if f.state != FindingState::Open {
                continue;
            }
            if f.last_revision.as_ref() != Some(&head_rev) {
                continue;
            }
            if ignore.iter().any(|i| i == &f.fingerprint) {
                continue;
            }
            let on_baseline = baseline.iter().any(|b| b == &f.fingerprint);
            // A new Finding in a build-only dependency is real debt, so it is
            // still Open and still annotated — it just does not block a merge
            // nobody is any less safe for making. Neither does a credential the
            // provider has already stopped accepting.
            let gates = (f.scope().gates() || gate_dev_scope) && !f.is_dead_secret();
            // A credential somebody can use right now is an incident, not debt:
            // it blocks the merge even though it is on the Baseline.
            let live_secret = f.gates_regardless_of_baseline();
            let line = f.observations.iter().find_map(|o| o.line).unwrap_or(1);
            let detail = f
                .observations
                .first()
                .map(|o| o.message.as_str())
                .filter(|m| !m.is_empty())
                .unwrap_or(&f.fingerprint.problem_id);
            annotations.push(Annotation {
                fingerprint: f.fingerprint.display(),
                message: format!(
                    "{detail}\n\nFingerprint: {}\nDismiss with: /hq dismiss {}",
                    f.fingerprint.display(),
                    f.fingerprint.display()
                ),
                path: crate::domain::annotation_path(&f.fingerprint.location_key),
                start_line: line,
                end_line: line,
                // Known debt is a warning; only a Finding that is new to this
                // Target is what blocks the merge.
                level: if live_secret {
                    "failure"
                } else if on_baseline || !gates {
                    "warning"
                } else {
                    "failure"
                }
                .into(),
                title: annotation_title(f, gates),
            });
            if live_secret || (!on_baseline && gates) {
                new_open.push(f.fingerprint.clone());
            }
        }
        let conclusion = if new_open.is_empty() {
            "success"
        } else {
            "failure"
        };
        let summary = if new_open.is_empty() {
            "no new open findings".into()
        } else {
            format!(
                "blocking findings: {}",
                new_open
                    .iter()
                    .map(|f| f.display())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        self.github.upsert_check(CheckRun {
            repo: repo.to_string(),
            pr,
            head_sha: head.to_string(),
            conclusion: conclusion.into(),
            summary: summary.clone(),
            annotations,
        })?;
        Ok(format!("gate={conclusion} pr={pr} {summary}"))
    }

    pub fn handle_comment(
        &mut self,
        repo: &str,
        pr: u64,
        _author: &str,
        can_write: bool,
        body: &str,
    ) -> Result<String, String> {
        let body = body.trim();
        if !body.starts_with("/hq dismiss") {
            return Ok("ignored".into());
        }
        if !can_write {
            return Err("author cannot write the Target".into());
        }
        let rest = body.trim_start_matches("/hq dismiss").trim();
        let fp = if rest.contains('|') {
            Fingerprint::parse(rest).ok_or_else(|| "bad fingerprint".to_string())?
        } else {
            // /hq dismiss PROBLEM LOCATION
            let mut parts = rest.splitn(2, char::is_whitespace);
            let problem = parts.next().ok_or("missing problem id")?.to_string();
            let location = parts.next().ok_or("missing location key")?.to_string();
            Fingerprint::new(repo, problem, location)
        };
        let msg = self.dismiss(&fp)?;
        // Re-evaluate gate against the PR's last head if we have a check
        let head = self
            .store
            .state
            .finding(&fp)
            .and_then(|f| f.last_revision.clone())
            .map(|r| r.0);
        if let Some(head) = head {
            let _ = self.post_gate(repo, pr, &head, false, &[]);
        }
        Ok(msg)
    }

    pub fn intel_rescan(&mut self) -> Result<String, String> {
        self.intel_rescan_named(&["fake"], None)
    }

    pub fn intel_rescan_named(
        &mut self,
        engines: &[&str],
        workspace: Option<&std::path::Path>,
    ) -> Result<String, String> {
        let names: Vec<String> = self.store.state.targets.keys().cloned().collect();
        let mut out = Vec::new();
        for name in names {
            let rev = self.store.state.targets[&name].default_revision.0.clone();
            match self.scan_named(&name, Some(&rev), engines, workspace, false) {
                Ok(m) => out.push(m),
                Err(e) => out.push(format!("{name}: {e}")),
            }
        }
        if out.is_empty() {
            Ok("no targets".into())
        } else {
            Ok(out.join("\n"))
        }
    }

    /// Queue a Scan of every Target's default Revision.
    ///
    /// Intel moves — a CVE published today makes yesterday's clean Scan wrong —
    /// so every Target is rescanned. They go on the queue rather than running
    /// one after another, so a thousand Targets is a throughput problem for the
    /// workers and not a command that runs for a day.
    pub fn queue_rescan(&mut self, engines: &[&str]) -> Result<String, String> {
        let queue = self.store.queue();
        let mut out = Vec::new();
        let targets: Vec<(String, String)> = self
            .store
            .state
            .targets
            .iter()
            .map(|(name, t)| (name.clone(), t.default_revision.0.clone()))
            .collect();
        for (name, revision) in targets {
            let id = queue.enqueue(&crate::queue::JobRequest {
                target: name.clone(),
                revision: revision.clone(),
                engines: engines.iter().map(|e| e.to_string()).collect(),
                purpose: crate::queue::Purpose::Default,
                pr_number: None,
                base_revision: None,
            })?;
            out.push(format!("queued {name}@{revision} scan={id}"));
        }
        if out.is_empty() {
            Ok("no targets".into())
        } else {
            Ok(out.join("\n"))
        }
    }

    pub fn github_dump(&self) -> String {
        serde_json::to_string_pretty(&self.github.dump()).unwrap()
    }
}
