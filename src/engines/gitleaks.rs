use crate::domain::{FindingKind, Observation, Revision, Target};
use crate::engine::{Engine, EngineError};
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
        let out = Command::new("gitleaks")
            .args([
                "detect",
                "--no-git",
                "-s",
                &dir.display().to_string(),
                "-f",
                "json",
                "--exit-code",
                "0",
            ])
            .output()
            .map_err(|_| EngineError::Failed("gitleaks".into()))?;
        let raw = String::from_utf8_lossy(&out.stdout);
        observations_from_json(&raw)
    }
}
