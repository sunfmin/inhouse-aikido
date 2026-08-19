use crate::domain::{FindingKind, LeakedSecret, Observation, Revision, Severity, Target};
use crate::engine::{engine_timeout, run_with_timeout, Engine, EngineError};
use serde::Deserialize;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Deserialize)]
pub struct GitleaksHit {
    #[serde(rename = "RuleID", alias = "ruleID", alias = "rule")]
    pub rule_id: Option<String>,
    #[serde(rename = "File", alias = "file")]
    pub file: Option<String>,
    #[serde(rename = "Description", alias = "description")]
    pub description: Option<String>,
    #[serde(rename = "StartLine", alias = "startLine")]
    pub start_line: Option<u32>,
    /// The matched credential. HQ uses it to ask the provider whether it still
    /// works, and then drops it — it is never stored.
    #[serde(rename = "Secret", alias = "secret")]
    pub secret: Option<String>,
}

pub fn observations_from_json(raw: &str) -> Result<Vec<Observation>, EngineError> {
    if raw.trim().is_empty() {
        return Ok(vec![]);
    }
    let hits: Vec<GitleaksHit> =
        serde_json::from_str(raw).map_err(|e| EngineError::Other(e.to_string()))?;
    Ok(hits
        .into_iter()
        .map(|h| {
            let file = h.file.unwrap_or_else(|| "unknown".into());
            Observation {
                engine: "gitleaks".into(),
                problem_id: h.rule_id.unwrap_or_else(|| "secret".into()),
                location_key: file,
                kind: FindingKind::Secret,
                package: None,
                manifest: None,
                fixed_version: None,
                message: h.description.unwrap_or_default(),
                // gitleaks counts from zero.
                line: h.start_line.map(|l| l + 1),
                scope: Default::default(),
                // gitleaks reports no severity. A live credential in a repo is
                // not a "medium", so HQ does not pretend it is unranked.
                severity: Severity::High,
                secret: h.secret.filter(|s| !s.is_empty()).map(LeakedSecret::new),
            }
        })
        .collect())
}

pub struct GitleaksEngine;

impl Engine for GitleaksEngine {
    fn name(&self) -> &str {
        "gitleaks"
    }

    fn scan(
        &self,
        _target: &Target,
        _revision: &Revision,
        workspace: Option<&Path>,
    ) -> Result<Vec<Observation>, EngineError> {
        let Some(dir) = workspace else {
            return Err(EngineError::Other("gitleaks requires --workspace".into()));
        };
        let report = std::env::temp_dir().join(format!("gitleaks-{}.json", std::process::id()));
        let git_dir = dir.join(".git");
        let mut cmd = Command::new("gitleaks");
        cmd.args([
            "detect",
            "-s",
            &dir.display().to_string(),
            "-f",
            "json",
            "--report-path",
            &report.display().to_string(),
            "--exit-code",
            "0",
        ]);
        if !git_dir.is_dir() {
            cmd.arg("--no-git");
        }
        let out = run_with_timeout(cmd, "gitleaks", engine_timeout())?;
        if !out.status.success() && !report.exists() {
            return Err(EngineError::Failed("gitleaks".into()));
        }
        let raw = if report.exists() {
            std::fs::read_to_string(&report).unwrap_or_default()
        } else {
            String::from_utf8_lossy(&out.stdout).into_owned()
        };
        let _ = std::fs::remove_file(&report);
        observations_from_json(&raw)
    }
}
