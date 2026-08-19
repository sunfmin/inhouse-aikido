use crate::domain::{Finding, FindingKind, FindingState};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct FindingView {
    pub fingerprint: String,
    pub target: String,
    pub problem_id: String,
    pub location_key: String,
    pub state: String,
    pub kind: String,
    /// runtime, development, or unknown — development-scope Findings do not
    /// block a merge, so an agent can leave them for later.
    pub scope: String,
    /// critical, high, medium, low, or unknown.
    pub severity: String,
    /// Published probability this CVE is exploited in the next 30 days.
    pub epss: Option<f64>,
    /// On CISA's Known Exploited Vulnerabilities list.
    pub known_exploited: bool,
    /// For a secret: active, inactive, or unverified.
    pub validity: String,
    pub engines: Vec<String>,
    pub package: Option<String>,
    pub manifest: Option<String>,
    pub fixed_version: Option<String>,
    pub last_revision: Option<String>,
    pub message: String,
    pub agent_fixable: bool,
}

impl FindingView {
    pub fn from_finding(f: &Finding) -> Self {
        let engines: Vec<String> = f.observations.iter().map(|o| o.engine.clone()).collect();
        let message = f
            .observations
            .iter()
            .map(|o| o.message.as_str())
            .find(|m| !m.is_empty())
            .unwrap_or("")
            .to_string();
        Self {
            scope: f.scope().as_str().to_string(),
            severity: f.severity.as_str().to_string(),
            epss: f.epss,
            known_exploited: f.known_exploited,
            validity: f.validity.as_str().to_string(),
            fingerprint: f.fingerprint.display(),
            target: f.fingerprint.target.clone(),
            problem_id: f.fingerprint.problem_id.clone(),
            location_key: f.fingerprint.location_key.clone(),
            state: match f.state {
                FindingState::Open => "open".into(),
                FindingState::Fixed => "fixed".into(),
                FindingState::Dismissed => "dismissed".into(),
            },
            kind: match f.kind {
                FindingKind::Sca => "sca".into(),
                FindingKind::Secret => "secret".into(),
                FindingKind::Sast => "sast".into(),
                FindingKind::Iac => "iac".into(),
                FindingKind::License => "license".into(),
            },
            engines,
            package: f.package.clone(),
            manifest: f.manifest.clone(),
            fixed_version: f.fixed_version.clone(),
            last_revision: f.last_revision.as_ref().map(|r| r.0.clone()),
            message,
            agent_fixable: is_agent_fixable(f),
        }
    }
}

pub fn is_agent_fixable(f: &Finding) -> bool {
    if f.state != FindingState::Open {
        return false;
    }
    match f.kind {
        FindingKind::Sast | FindingKind::Secret | FindingKind::Iac => true,
        FindingKind::Sca => f.fixed_version.is_some(),
        FindingKind::License => false,
    }
}

/// Lower is earlier in the pickup queue.
pub fn pickup_rank(f: &Finding) -> u8 {
    match f.kind {
        FindingKind::Secret => 0,
        FindingKind::Sast => 1,
        FindingKind::Sca => 2,
        FindingKind::Iac => 3,
        FindingKind::License => 9,
    }
}

pub fn brief_markdown(f: &Finding) -> String {
    let v = FindingView::from_finding(f);
    let (summary, current, desired, interfaces, criteria, out) = match f.kind {
        FindingKind::Sca => {
            let pkg = v.package.as_deref().unwrap_or("the package");
            let pin = v.fixed_version.as_deref().unwrap_or("a known fixed version");
            let manifest = v.manifest.as_deref().unwrap_or("the lockfile");
            (
                format!("Pin {pkg} to {pin} so {problem} is gone", problem = v.problem_id),
                format!(
                    "{manifest} still resolves {pkg} to a release that carries {problem}.",
                    problem = v.problem_id
                ),
                format!("The lockfile / manifest pins {pkg} at {pin} (or newer that still fixes {problem}) and a HQ rescan no longer reports this Fingerprint as Open.", problem = v.problem_id),
                format!("- Manifest location key: `{loc}`\n- Package: `{pkg}`\n- Required pin: `{pin}`\n- Do not invent a different package name", loc = v.location_key),
                format!("- [ ] `{pkg}` is pinned to `{pin}` or a newer fixed release in `{manifest}`\n- [ ] `hq scan` of this Target no longer lists Fingerprint `{fp}` as Open\n- [ ] Lockfile / install still resolves", fp = v.fingerprint),
                "- Changing unrelated dependencies\n- Dismissing the Finding instead of fixing it\n- Opening a HQ Remediation PR if you are the agent (do the pin yourself)".to_string(),
            )
        }
        FindingKind::Secret => (
            format!("Remove leaked credential {} and rotate it", v.problem_id),
            format!(
                "A secret matching rule `{}` is in the tree at `{}`.",
                v.problem_id, v.location_key
            ),
            "The secret is gone from the tree (and git history is noted if it was committed). The credential is rotated at the provider. A HQ Gitleaks Scan does not reopen this Fingerprint.".into(),
            format!("- Location key (file): `{}`\n- Rule: `{}`\n- Do not print, log, or commit the secret value", v.location_key, v.problem_id),
            format!("- [ ] File `{}` no longer contains the leaked secret\n- [ ] Replacement uses a secret store / env, not a literal\n- [ ] `hq scan --use gitleaks` does not report Fingerprint `{}` as Open", v.location_key, v.fingerprint),
            "- Publishing the secret in the PR or brief\n- Only deleting the line without rotating the credential\n- Dismissing instead of fixing".to_string(),
        ),
        FindingKind::Sast => {
            let hint = if v.message.is_empty() {
                v.problem_id.clone()
            } else {
                v.message.clone()
            };
            (
                format!("Fix SAST rule {} at {}", v.problem_id, v.location_key),
                format!(
                    "Opengrep reports `{}` at `{}`. {}",
                    v.problem_id, v.location_key, hint
                ),
                "The code no longer matches the rule. Behavior stays correct. HQ SAST Scan does not report this Fingerprint as Open.".into(),
                format!("- Location key (source file): `{}`\n- Rule: `{}`\n- Engine note: {}", v.location_key, v.problem_id, hint),
                format!("- [ ] `{}` no longer matches `{}`\n- [ ] Existing tests for that area still pass\n- [ ] `hq scan --use opengrep` does not report Fingerprint `{}` as Open", v.location_key, v.problem_id, v.fingerprint),
                "- Rewriting unrelated files\n- Disabling the rule globally\n- Dismissing instead of fixing".to_string(),
            )
        }
        FindingKind::Iac => (
            format!("Fix IaC rule {} at {}", v.problem_id, v.location_key),
            format!("Trivy reports misconfiguration `{}` at `{}`.", v.problem_id, v.location_key),
            "The manifest satisfies the rule. HQ Scan does not report this Fingerprint as Open.".into(),
            format!("- Location key: `{}`\n- Rule: `{}`", v.location_key, v.problem_id),
            format!("- [ ] The IaC at `{}` no longer matches `{}`\n- [ ] `hq scan --use trivy` does not report Fingerprint `{}` as Open", v.location_key, v.problem_id, v.fingerprint),
            "- Dismissing instead of fixing\n- Changing unrelated infrastructure".to_string(),
        ),
        FindingKind::License => (
            format!("License {} at {} needs a human decision", v.problem_id, v.location_key),
            format!(
                "Package `{}` in `{}` is licensed `{}`.",
                v.package.as_deref().unwrap_or("?"),
                v.manifest.as_deref().unwrap_or(v.location_key.as_str()),
                v.problem_id
            ),
            "An Operator has either accepted the license or replaced the package. Agents do not Dismiss license Findings.".into(),
            format!("- Package: `{}`\n- License: `{}`", v.package.as_deref().unwrap_or("?"), v.problem_id),
            "- [ ] Operator recorded a decision (replace or accept)\n- [ ] If replaced, HQ Scan no longer reports this Fingerprint as Open".into(),
            "- Auto-accepting a license\n- Dismissing without an Operator".to_string(),
        ),
    };

    format!(
        "## Agent Brief\n\n\
         **Category:** {cat}\n\
         **Summary:** {summary}\n\n\
         **Fingerprint:** `{fp}`\n\
         **Target:** `{target}`\n\
         **Kind:** {kind}\n\
         **State:** {state}\n\
         **Engines:** {engines}\n\
         **Agent-fixable:** {fixable}\n\n\
         **Current behavior:**\n{current}\n\n\
         **Desired behavior:**\n{desired}\n\n\
         **Key interfaces:**\n{interfaces}\n\n\
         **Acceptance criteria:**\n{criteria}\n\n\
         **Out of scope:**\n{out}\n\n\
         **Verify:** after the change, from the Target workspace run\n\
         `hq scan {target} --workspace . --use gitleaks,trivy,opengrep`\n\
         then `hq show {fp}` and confirm state is no longer Open.\n\
         Do not `hq dismiss` this Finding.\n",
        cat = if f.kind == FindingKind::Secret || f.kind == FindingKind::Sast {
            "bug"
        } else {
            "enhancement"
        },
        summary = summary,
        fp = v.fingerprint,
        target = v.target,
        kind = v.kind,
        state = v.state,
        engines = v.engines.join(","),
        fixable = v.agent_fixable,
        current = current,
        desired = desired,
        interfaces = interfaces,
        criteria = criteria,
        out = out,
    )
}
