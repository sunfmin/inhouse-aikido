//! Getting a Target's Revision onto disk so Engines can look at it.
//!
//! HQ clones the repo itself, with the App's installation token, into a
//! directory it removes afterwards. The token goes in through git's environment
//! config, never into a remote URL or `.git/config`, so nothing on disk or in
//! `ps` output carries it.

use crate::github::app::AppAuth;
use base64::Engine as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

const DEFAULT_CLONE_BASE: &str = "https://github.com";

/// A checked-out Revision. Removed when it goes out of scope, including when a
/// Scan fails partway.
#[derive(Debug)]
pub struct Workspace {
    dir: tempfile::TempDir,
}

impl Workspace {
    pub fn path(&self) -> &Path {
        self.dir.path()
    }
}

/// Where a Revision comes from.
pub trait Checkout: Send + Sync {
    /// Put `revision` of `repo` on disk. `revision` may be a branch name or an
    /// exact commit.
    fn checkout(&mut self, repo: &str, revision: &str) -> Result<Workspace, String>;
}

/// Hands out installation tokens for cloning. `None` means clone anonymously,
/// which is all a public Target needs.
pub trait Tokens: Send + Sync {
    fn token_for(&mut self, repo: &str) -> Result<Option<String>, String>;
}

/// No credentials: public repositories and local development.
pub struct Anonymous;

impl Tokens for Anonymous {
    fn token_for(&mut self, _repo: &str) -> Result<Option<String>, String> {
        Ok(None)
    }
}

impl Tokens for Arc<Mutex<AppAuth>> {
    fn token_for(&mut self, repo: &str) -> Result<Option<String>, String> {
        let mut auth = self.lock().map_err(|_| "App auth is poisoned".to_string())?;
        let installation = auth.installation_id_for_repo(repo)?;
        auth.installation_token(installation).map(Some)
    }
}

pub struct GitCheckout {
    tokens: Box<dyn Tokens>,
    clone_base: String,
}

impl Default for GitCheckout {
    fn default() -> Self {
        Self::new(Box::new(Anonymous))
    }
}

impl GitCheckout {
    pub fn new(tokens: Box<dyn Tokens>) -> Self {
        Self {
            tokens,
            clone_base: std::env::var("HQ_GITHUB_CLONE_BASE")
                .unwrap_or_else(|_| DEFAULT_CLONE_BASE.to_string()),
        }
    }

    pub fn with_clone_base(mut self, base: impl Into<String>) -> Self {
        self.clone_base = base.into();
        self
    }

    fn remote_url(&self, repo: &str) -> String {
        let base = self.clone_base.trim_end_matches('/');
        if base.starts_with("file:") || base.starts_with('/') {
            format!("{base}/{repo}")
        } else {
            format!("{base}/{repo}.git")
        }
    }
}

/// Run one git command, with the token supplied through the environment so it
/// never reaches argv or `.git/config`.
fn git(dir: &Path, token: Option<&str>, args: &[&str]) -> Result<(), String> {
    let mut cmd = Command::new("git");
    cmd.current_dir(dir).args(args);
    if let Some(token) = token {
        let basic = base64::engine::general_purpose::STANDARD
            .encode(format!("x-access-token:{token}").as_bytes());
        cmd.env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "http.extraheader")
            .env("GIT_CONFIG_VALUE_0", format!("Authorization: Basic {basic}"));
    }
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    let out = cmd
        .output()
        .map_err(|e| format!("cannot run git: {e} — is git on PATH?"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "git {} failed: {}",
            args.first().copied().unwrap_or("?"),
            redact(&stderr, token).trim()
        ));
    }
    Ok(())
}

/// Never let a credential reach an error message, whatever git printed.
fn redact(text: &str, token: Option<&str>) -> String {
    match token {
        Some(t) if !t.is_empty() => text.replace(t, "<redacted>"),
        _ => text.to_string(),
    }
}

impl Checkout for GitCheckout {
    fn checkout(&mut self, repo: &str, revision: &str) -> Result<Workspace, String> {
        let token = self.tokens.token_for(repo)?;
        let dir = tempfile::Builder::new()
            .prefix("hq-scan-")
            .tempdir()
            .map_err(|e| format!("cannot make a workspace: {e}"))?;
        let path: PathBuf = dir.path().to_path_buf();
        let url = self.remote_url(repo);

        git(&path, None, &["init", "--quiet"])?;
        git(&path, None, &["remote", "add", "origin", &url])?;
        // One Revision, no history: a Scan looks at a snapshot, not a timeline.
        // `revision` may be a branch or an exact commit; GitHub serves both.
        git(
            &path,
            token.as_deref(),
            &["fetch", "--depth", "1", "--quiet", "origin", revision],
        )
        .map_err(|e| format!("cannot fetch {revision} of {repo}: {e}"))?;
        git(&path, None, &["checkout", "--quiet", "FETCH_HEAD"])?;

        Ok(Workspace { dir })
    }
}
