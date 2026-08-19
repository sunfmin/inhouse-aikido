use crate::domain::{Observation, Revision, Target};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("engine {0} failed")]
    Failed(String),
    #[error("engine {0} timed out")]
    TimedOut(String),
    #[error("{0}")]
    Other(String),
}

impl EngineError {
    /// The Engine this error is about, for the Scan record.
    pub fn engine(&self) -> String {
        match self {
            EngineError::Failed(n) | EngineError::TimedOut(n) | EngineError::Other(n) => n.clone(),
        }
    }
}

/// How long a single Engine may run before HQ gives up on it. An Engine that
/// hangs must become a failed Scan, not a Scan that never ends.
pub fn engine_timeout() -> Duration {
    let secs = std::env::var("HQ_ENGINE_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(600);
    Duration::from_secs(secs)
}

/// Run an Engine's binary, killing it if it outruns the timeout.
///
/// stdout and stderr are drained on their own threads: an Engine that fills a
/// pipe while HQ waits on the process would deadlock otherwise.
pub fn run_with_timeout(
    mut command: Command,
    engine: &str,
    timeout: Duration,
) -> Result<Output, EngineError> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| EngineError::Failed(engine.to_string()))?;

    let mut out = child.stdout.take();
    let mut err = child.stderr.take();
    let drain_out = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(handle) = out.as_mut() {
            use std::io::Read;
            let _ = handle.read_to_end(&mut buf);
        }
        buf
    });
    let drain_err = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(handle) = err.as_mut() {
            use std::io::Read;
            let _ = handle.read_to_end(&mut buf);
        }
        buf
    });

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => {
                let _ = child.kill();
                break None;
            }
        }
    };

    let stdout = drain_out.join().unwrap_or_default();
    let stderr = drain_err.join().unwrap_or_default();
    match status {
        Some(status) => Ok(Output {
            status,
            stdout,
            stderr,
        }),
        None => Err(EngineError::TimedOut(engine.to_string())),
    }
}

pub trait Engine: Send + Sync {
    fn name(&self) -> &str;

    /// Does this Engine read the Target's files? An Engine that does makes HQ
    /// clone the Revision; one that does not (the fake, or an image scan) does
    /// not pay for a checkout.
    fn needs_workspace(&self) -> bool {
        true
    }

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

    fn needs_workspace(&self) -> bool {
        false
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
