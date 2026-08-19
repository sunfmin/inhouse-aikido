use crate::domain::{dependency_location, FindingKind, Observation, Revision, Target};
use crate::engine::{engine_timeout, run_with_timeout, Engine, EngineError};
use serde::Deserialize;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Deserialize)]
pub struct TrivyReport {
    #[serde(default, rename = "Results")]
    pub results: Vec<TrivyResult>,
}

#[derive(Debug, Deserialize)]
pub struct TrivyResult {
    #[serde(default, rename = "Target")]
    pub target: String,
    #[serde(default, rename = "Class")]
    pub class: Option<String>,
    #[serde(default, rename = "Vulnerabilities")]
    pub vulnerabilities: Option<Vec<TrivyVuln>>,
    #[serde(default, rename = "Misconfigurations")]
    pub misconfigurations: Option<Vec<TrivyMisconfig>>,
    #[serde(default, rename = "Secrets")]
    pub secrets: Option<Vec<TrivySecret>>,
    #[serde(default, rename = "Licenses")]
    pub licenses: Option<Vec<TrivyLicense>>,
}

#[derive(Debug, Deserialize)]
pub struct TrivyLicense {
    #[serde(default, rename = "Name")]
    pub license: Option<String>,
    #[serde(default, rename = "PkgName")]
    pub pkg: Option<String>,
    #[serde(default, rename = "FilePath")]
    pub file: Option<String>,
    #[serde(default, rename = "Category")]
    pub category: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TrivyVuln {
    #[serde(rename = "VulnerabilityID")]
    pub id: String,
    #[serde(rename = "PkgName")]
    pub pkg: String,
    #[serde(default, rename = "FixedVersion")]
    pub fixed: Option<String>,
    #[serde(default, rename = "Title")]
    pub title: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TrivyMisconfig {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(default, rename = "Title")]
    pub title: Option<String>,
    #[serde(default, rename = "CauseMetadata")]
    pub cause: Option<TrivyCause>,
}

#[derive(Debug, Deserialize)]
pub struct TrivyCause {
    #[serde(default, rename = "StartLine")]
    pub start_line: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct TrivySecret {
    #[serde(rename = "RuleID")]
    pub id: String,
    #[serde(default, rename = "Title")]
    pub title: Option<String>,
}

pub fn observations_from_json(raw: &str) -> Result<Vec<Observation>, EngineError> {
    if raw.trim().is_empty() {
        return Ok(vec![]);
    }
    let report: TrivyReport =
        serde_json::from_str(raw).map_err(|e| EngineError::Other(e.to_string()))?;
    let mut out = Vec::new();
    for result in report.results {
        let manifest = result.target.clone();
        if let Some(vulns) = result.vulnerabilities {
            for v in vulns {
                let fixed = v.fixed.filter(|s| !s.is_empty());
                out.push(Observation {
                    engine: "trivy".into(),
                    problem_id: v.id,
                    location_key: dependency_location(&manifest, &v.pkg),
                    kind: FindingKind::Sca,
                    package: Some(v.pkg),
                    manifest: Some(manifest.clone()),
                    fixed_version: fixed,
                    message: v.title.unwrap_or_default(),
                    // A lockfile CVE is about the entry, not a line.
                    line: None,
                });
            }
        }
        if let Some(mis) = result.misconfigurations {
            for m in mis {
                let line = m.cause.and_then(|c| c.start_line).filter(|l| *l > 0);
                out.push(Observation {
                    engine: "trivy".into(),
                    problem_id: m.id,
                    location_key: manifest.clone(),
                    kind: FindingKind::Iac,
                    package: None,
                    manifest: Some(manifest.clone()),
                    fixed_version: None,
                    message: m.title.unwrap_or_default(),
                    line,
                });
            }
        }
        if let Some(licenses) = result.licenses {
            for lic in licenses {
                let pkg = lic.pkg.clone().unwrap_or_else(|| "unknown".into());
                let license = lic.license.clone().unwrap_or_else(|| "unknown".into());
                let loc = lic
                    .file
                    .as_deref()
                    .map(|f| dependency_location(f, &pkg))
                    .unwrap_or_else(|| dependency_location(&manifest, &pkg));
                out.push(Observation {
                    engine: "trivy".into(),
                    problem_id: license,
                    location_key: loc,
                    kind: FindingKind::License,
                    package: Some(pkg),
                    manifest: Some(manifest.clone()),
                    fixed_version: None,
                    message: lic.category.unwrap_or_default(),
                    line: None,
                });
            }
        }
        let _ = result.secrets;
        let _ = result.class;
    }
    Ok(out)
}

pub struct TrivyEngine;

impl Engine for TrivyEngine {
    fn name(&self) -> &str {
        "trivy"
    }

    fn scan(
        &self,
        target: &Target,
        _revision: &Revision,
        workspace: Option<&Path>,
    ) -> Result<Vec<Observation>, EngineError> {
        let mut cmd = Command::new("trivy");
        match target.kind {
            crate::domain::TargetKind::Image => {
                cmd.args(["image", "--format", "json", "--quiet", &target.id.0]);
            }
            crate::domain::TargetKind::Github => {
                let dir = workspace
                    .ok_or_else(|| EngineError::Other("trivy fs requires --workspace".into()))?;
                cmd.args([
                    "fs",
                    "--scanners",
                    "vuln,misconfig,license",
                    "--skip-dirs",
                    "node_modules,dist,target,.git",
                    "--format",
                    "json",
                    "--quiet",
                    &dir.display().to_string(),
                ]);
            }
        }
        let out = run_with_timeout(cmd, "trivy", engine_timeout())?;
        if !out.status.success() && out.stdout.is_empty() {
            return Err(EngineError::Failed("trivy".into()));
        }
        observations_from_json(&String::from_utf8_lossy(&out.stdout))
    }
}
