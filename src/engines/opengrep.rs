use crate::domain::{FindingKind, Observation, Revision, Severity, Target};
use crate::engine::{engine_timeout, run_with_timeout, Engine, EngineError};
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
    pub start: Option<OpengrepPosition>,
    #[serde(default)]
    pub extra: Option<OpengrepExtra>,
}

#[derive(Debug, Deserialize)]
pub struct OpengrepPosition {
    #[serde(default)]
    pub line: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct OpengrepExtra {
    #[serde(default)]
    pub message: Option<String>,
    /// opengrep says ERROR / WARNING / INFO.
    #[serde(default)]
    pub severity: Option<String>,
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
        .map(|r| {
            let extra = r.extra;
            Observation {
                engine: "opengrep".into(),
                problem_id: r.check_id,
                location_key: r.path, // rewritten relative to workspace in scan()
                kind: FindingKind::Sast,
                package: None,
                manifest: None,
                fixed_version: None,
                line: r.start.and_then(|p| p.line),
                scope: Default::default(),
                severity: extra
                    .as_ref()
                    .and_then(|e| e.severity.as_deref())
                    .and_then(Severity::parse)
                    .unwrap_or(Severity::Unknown),
                secret: None,
                message: extra.and_then(|e| e.message).unwrap_or_default(),
            }
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
        let config = std::env::var("HQ_OPENGREP_CONFIG").unwrap_or_else(|_| {
            let bundled = Path::new(env!("CARGO_MANIFEST_DIR")).join("rules/opengrep");
            bundled.display().to_string()
        });
        let mut cmd = Command::new("opengrep");
        cmd.args([
            "scan",
            "--json",
            "--quiet",
            "--config",
            &config,
            &dir.display().to_string(),
        ]);
        let out = run_with_timeout(cmd, "opengrep", engine_timeout())?;
        if !out.status.success() && out.stdout.is_empty() {
            return Err(EngineError::Failed("opengrep".into()));
        }
        // Opengrep may print logs before JSON
        let stdout = String::from_utf8_lossy(&out.stdout);
        let raw = stdout
            .find('{')
            .map(|i| &stdout[i..])
            .unwrap_or(stdout.as_ref());
        let mut obs = observations_from_json(raw)?;
        let prefix = dir.display().to_string();
        for o in &mut obs {
            if let Some(rest) = o
                .location_key
                .strip_prefix(&prefix)
                .map(|s| s.trim_start_matches('/'))
            {
                o.location_key = rest.to_string();
            }
        }
        Ok(obs)
    }
}
