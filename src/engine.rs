use crate::domain::{Observation, Revision, Target};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("engine {0} failed")]
    Failed(String),
    #[error("{0}")]
    Other(String),
}

pub trait Engine: Send + Sync {
    fn name(&self) -> &str;
    fn scan(
        &self,
        target: &Target,
        revision: &Revision,
        workspace: Option<&std::path::Path>,
    ) -> Result<Vec<Observation>, EngineError>;
}

/// Observations keyed by "target@revision", used in tests and as the default Engine.
#[derive(Debug, Default, Clone)]
pub struct FakeEngine {
    pub name: String,
    pub by_key: std::collections::HashMap<String, Vec<Observation>>,
    pub fail: std::collections::HashSet<String>,
}

impl FakeEngine {
    pub fn key(target: &str, revision: &str) -> String {
        format!("{target}@{revision}")
    }
}

impl Engine for FakeEngine {
    fn name(&self) -> &str {
        &self.name
    }

    fn scan(
        &self,
        target: &Target,
        revision: &Revision,
        _workspace: Option<&std::path::Path>,
    ) -> Result<Vec<Observation>, EngineError> {
        let key = Self::key(&target.id.0, &revision.0);
        if self.fail.contains(&key) {
            return Err(EngineError::Failed(self.name.clone()));
        }
        Ok(self.by_key.get(&key).cloned().unwrap_or_default())
    }
}
