use crate::domain::{FindingKind, Observation, Revision, Target};
use crate::engine::{Engine, EngineError};
use serde::Deserialize;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Deserialize)]
pub struct OpengrepReport {
    #[serde(default)]
    pub results: Vec<OpengrepResult>,
}

#[derive(Debug, Deserialize)]
pub struct OpengrepResult {
    pub check_id: String,
    pub path: String,
    #[serde(default)]
    pub extra: Option<OpengrepExtra>,
}

#[derive(Debug, Deserialize)]
pub struct OpengrepExtra {
    #[serde(default)]
    pub message: Option<String>,
}

pub fn observations_from_json(raw: &str) -> Result<Vec<Observation>, EngineError> {
    if raw.trim().is_empty() {
        return Ok(vec![]);
    }
    let report: OpengrepReport =
        serde_json::from_str(raw).map_err(|e| EngineError::Other(e.to_string()))?;
    Ok(report
        .results
        .into_iter()
        .map(|r| Observation {
            engine: "opengrep".into(),
            problem_id: r.check_id,
            location_key: r.path,
            kind: FindingKind::Sast,
            package: None,
            manifest: None,
            fixed_version: None,
            message: r.extra.and_then(|e| e.message).unwrap_or_default(),
        })
        .collect())
}

pub struct OpengrepEngine;

impl Engine for OpengrepEngine {
    fn name(&self) -> &str {
        "opengrep"
    }

    fn scan(
        &self,
        _target: &Target,
        _revision: &Revision,
        workspace: Option<&Path>,
    ) -> Result<Vec<Observation>, EngineError> {
        let dir =
            workspace.ok_or_else(|| EngineError::Other("opengrep requires --workspace".into()))?;
        let out = Command::new("opengrep")
            .args(["--json", "--quiet", &dir.display().to_string()])
            .output()
            .map_err(|_| EngineError::Failed("opengrep".into()))?;
        if !out.status.success() && out.stdout.is_empty() {
            // try semgrep-compatible binary name
            let out = Command::new("semgrep")
                .args([
                    "--config",
                    "auto",
                    "--json",
                    "--quiet",
                    &dir.display().to_string(),
                ])
                .output()
                .map_err(|_| EngineError::Failed("opengrep".into()))?;
            return observations_from_json(&String::from_utf8_lossy(&out.stdout));
        }
        observations_from_json(&String::from_utf8_lossy(&out.stdout))
    }
}
