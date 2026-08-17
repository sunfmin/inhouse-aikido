use crate::domain::{Finding, Fingerprint, Remediation, Target};
use crate::engine::FakeEngine;
use crate::github::FakeGithub;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct State {
    pub targets: HashMap<String, Target>,
    pub findings: HashMap<String, Finding>,
    pub remediations: Vec<Remediation>,
    pub github: FakeGithub,
    pub fake: FakeBundle,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FakeBundle {
    pub observations: HashMap<String, Vec<crate::domain::Observation>>,
    pub fail: Vec<String>,
}

impl State {
    pub fn finding(&self, fp: &Fingerprint) -> Option<&Finding> {
        self.findings.get(&fp.display())
    }

    pub fn finding_mut(&mut self, fp: &Fingerprint) -> Option<&mut Finding> {
        self.findings.get_mut(&fp.display())
    }
}

pub struct Store {
    path: PathBuf,
    pub state: State,
}

impl Store {
    pub fn open(dir: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let path = dir.join("state.json");
        let state = if path.exists() {
            let raw = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
            serde_json::from_str(&raw).map_err(|e| e.to_string())?
        } else {
            State::default()
        };
        Ok(Self { path, state })
    }

    pub fn save(&self) -> Result<(), String> {
        let raw = serde_json::to_string_pretty(&self.state).map_err(|e| e.to_string())?;
        std::fs::write(&self.path, raw).map_err(|e| e.to_string())
    }

    pub fn fake_engine(&self, name: &str) -> FakeEngine {
        FakeEngine {
            name: name.to_string(),
            by_key: self.state.fake.observations.clone(),
            fail: self.state.fake.fail.iter().cloned().collect(),
        }
    }
}
