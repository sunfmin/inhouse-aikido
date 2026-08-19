use crate::domain::{
    Annotation, CheckRun, Finding, FindingKind, FindingState, Fingerprint, Observation, PrFile,
    Remediation, Revision, Target, TargetId, TargetKind,
};
use crate::engine::{Engine, EngineError, FakeEngine};
use crate::github::Github;
use crate::store::Store;
use crate::workspace::{Checkout, GitCheckout, Workspace};

pub struct Hq {
    pub store: Store,
    /// Chosen when HQ is constructed, never loaded from the Store's state.
    pub github: Box<dyn Github>,
    /// How a Revision gets onto disk when nobody hands HQ a workspace.
    pub checkout: Box<dyn Checkout>,
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
        })
    }

    /// Use a different way of getting a Revision onto disk.
    pub fn with_checkout(mut self, checkout: Box<dyn Checkout>) -> Self {
        self.checkout = checkout;
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
                    "{} kind={:?} default={} baseline_ready={}",
                    t.id.0, t.kind, t.default_revision.0, t.baseline_ready
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

    fn select_engines(&self, names: &[&str]) -> Vec<Box<dyn Engine>> {
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
                Err(EngineError::Failed(n)) | Err(EngineError::Other(n)) => failed.push(n),
            }
        }
        if !failed.is_empty() {
            return Err(format!("engines failed: {}", failed.join(",")));
        }
        let was_baseline = target.baseline_ready;
        self.apply_observations(name, &rev, &observations, is_pr);
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
            let opened = self.maybe_remediate(name)?;
            if opened > 0 {
                msg.push_str(&format!(" remediations={opened}"));
            }
        }
        Ok(msg)
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

    fn maybe_remediate(&mut self, target: &str) -> Result<usize, String> {
        // A backend that cannot open a PR opens none, rather than recording a
        // Remediation nobody can merge.
        if !self.github.can_open_pr() {
            return Ok(0);
        }
        let t = self.store.state.targets.get(target).unwrap();
        if !t.baseline_ready {
            return Ok(0);
        }
        if t.kind != TargetKind::Github {
            return Ok(0);
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

        for ((manifest, package, fixed), fps) in groups {
            if existing
                .iter()
                .any(|(m, p, v)| m == &manifest && p == &package && v == &fixed)
            {
                continue;
            }
            let title = format!("Remediation: pin {package} to {fixed} in {manifest}");
            let body = format!(
                "Safe pin-bump for {}.\n\nFindings:\n{}",
                target,
                fps.iter()
                    .map(|f| format!("- {}", f.display()))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
            let files = vec![PrFile {
                path: manifest.clone(),
                content: format!("# pin {package} = {fixed}\n"),
            }];
            let pr = self.github.open_pr(target, &title, &body, files)?;
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
        Ok(opened)
    }

    fn filtered_findings(
        &self,
        target: Option<&str>,
        state: Option<&str>,
        kind: Option<&str>,
    ) -> Vec<&Finding> {
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
            .collect();
        items.sort_by_key(|f| f.fingerprint.display());
        items
    }

    pub fn findings_text(
        &self,
        target: Option<&str>,
        state: Option<&str>,
        kind: Option<&str>,
    ) -> String {
        let items = self.filtered_findings(target, state, kind);
        if items.is_empty() {
            return "no findings".into();
        }
        items
            .iter()
            .map(|f| {
                let engines: Vec<&str> = f.observations.iter().map(|o| o.engine.as_str()).collect();
                format!(
                    "{} state={:?} kind={:?} engines={}",
                    f.fingerprint.display(),
                    f.state,
                    f.kind,
                    engines.join(",")
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn findings_json(
        &self,
        target: Option<&str>,
        state: Option<&str>,
        kind: Option<&str>,
    ) -> Result<String, String> {
        let views: Vec<crate::brief::FindingView> = self
            .filtered_findings(target, state, kind)
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
        items.sort_by_key(|f| (crate::brief::pickup_rank(f), f.fingerprint.display()));
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
                level: if on_baseline { "warning" } else { "failure" }.into(),
                title: format!("{:?} {}", f.kind, f.fingerprint.problem_id),
            });
            if !on_baseline {
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
                "new open findings: {}",
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

    pub fn github_dump(&self) -> String {
        serde_json::to_string_pretty(&self.github.dump()).unwrap()
    }
}
