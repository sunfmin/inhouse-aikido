//! The GitHub backend that actually writes to GitHub.
//!
//! HQ's Gate is a Check Run on the PR's head Revision, named `hq`. There is one
//! per Revision: a second Scan of the same Revision updates it rather than
//! stacking another. Annotations go up in the batches the API accepts.

use crate::domain::{Annotation, CheckRun, PrRequest};
use crate::github::app::{AppAuth, Method};
use crate::github::Github;
use std::sync::{Arc, Mutex};

/// The Check Run's name on GitHub. A Developer looks for this in the checks list.
pub const CHECK_NAME: &str = "hq";
/// GitHub accepts at most this many annotations per request.
const ANNOTATION_BATCH: usize = 50;
/// GitHub truncates a longer annotation title.
const TITLE_LIMIT: usize = 255;

pub struct RealGithub {
    /// Shared with whatever else needs installation tokens — the checkout, in
    /// particular — so one token is minted per installation, not one per user.
    auth: Arc<Mutex<AppAuth>>,
}

impl RealGithub {
    pub fn new(auth: Arc<Mutex<AppAuth>>) -> Self {
        Self { auth }
    }

    pub fn from_env() -> Result<Self, String> {
        Ok(Self::new(Arc::new(Mutex::new(AppAuth::from_env()?))))
    }

    fn call(
        &self,
        repo: &str,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, String> {
        self.auth
            .lock()
            .map_err(|_| "App auth is poisoned".to_string())?
            .call_for_repo(repo, method, path, body)
    }

    /// The id of the Check Run HQ already wrote for this Revision, if any.
    fn existing_check(&mut self, repo: &str, head_sha: &str) -> Result<Option<u64>, String> {
        let path = format!("/repos/{repo}/commits/{head_sha}/check-runs?check_name={CHECK_NAME}");
        let body = self.call(repo, Method::Get, &path, None)?;
        Ok(body
            .get("check_runs")
            .and_then(|r| r.as_array())
            .and_then(|runs| runs.first())
            .and_then(|run| run.get("id"))
            .and_then(|id| id.as_u64()))
    }
}

/// GitHub wants `owner:branch` when filtering pull requests by head.
fn head_filter(repo: &str, branch: &str) -> String {
    let owner = repo.split('/').next().unwrap_or(repo);
    format!("{owner}:{branch}")
}

fn annotation_json(a: &Annotation) -> serde_json::Value {
    let level = match a.level.as_str() {
        "failure" | "warning" | "notice" => a.level.as_str(),
        _ => "warning",
    };
    serde_json::json!({
        "path": a.path,
        "start_line": a.start_line.max(1),
        "end_line": a.end_line.max(a.start_line).max(1),
        "annotation_level": level,
        "title": a.title.chars().take(TITLE_LIMIT).collect::<String>(),
        "message": a.message,
    })
}

fn output(check: &CheckRun, annotations: &[Annotation]) -> serde_json::Value {
    let title = if check.conclusion == "success" {
        "No new Findings".to_string()
    } else {
        format!("{} — merge blocked", check.summary)
    };
    serde_json::json!({
        "title": title.chars().take(TITLE_LIMIT).collect::<String>(),
        "summary": check.summary,
        "annotations": annotations.iter().map(annotation_json).collect::<Vec<_>>(),
    })
}

impl Github for RealGithub {
    fn backend(&self) -> &str {
        "github"
    }

    fn upsert_check(&mut self, check: CheckRun) -> Result<(), String> {
        if check.head_sha.is_empty() {
            return Err(format!(
                "cannot write the Gate for {} PR {}: no head Revision",
                check.repo, check.pr
            ));
        }
        let mut batches = check.annotations.chunks(ANNOTATION_BATCH);
        let first = batches.next().unwrap_or(&[]);

        let existing = self.existing_check(&check.repo, &check.head_sha)?;
        let payload = serde_json::json!({
            "name": CHECK_NAME,
            "head_sha": check.head_sha,
            "status": "completed",
            "conclusion": check.conclusion,
            "output": output(&check, first),
        });
        let run = match existing {
            Some(id) => {
                let path = format!("/repos/{}/check-runs/{id}", check.repo);
                self.call(&check.repo, Method::Patch, &path, Some(payload))?;
                id
            }
            None => {
                let path = format!("/repos/{}/check-runs", check.repo);
                let created = self.call(&check.repo, Method::Post, &path, Some(payload))?;
                created
                    .get("id")
                    .and_then(|id| id.as_u64())
                    .ok_or_else(|| "GitHub created a Check Run without an id".to_string())?
            }
        };

        // Anything past the first batch goes up as an update to the same run,
        // so a Finding is never silently dropped for being the 51st.
        for batch in batches {
            let path = format!("/repos/{}/check-runs/{run}", check.repo);
            let payload = serde_json::json!({ "output": output(&check, batch) });
            self.call(&check.repo, Method::Patch, &path, Some(payload))?;
        }
        Ok(())
    }

    fn open_pr(&mut self, request: PrRequest) -> Result<u64, String> {
        let path = format!("/repos/{}/pulls", request.repo);
        let payload = serde_json::json!({
            "title": request.title,
            "body": request.body,
            "head": request.head,
            "base": request.base,
        });
        let opened = self.call(&request.repo, Method::Post, &path, Some(payload))?;
        if let Some(number) = opened.get("number").and_then(|n| n.as_u64()) {
            return Ok(number);
        }
        // GitHub refuses a second PR for a branch that already has one open.
        // That PR is the Remediation; find it rather than opening another.
        let path = format!(
            "/repos/{}/pulls?state=open&head={}",
            request.repo,
            head_filter(&request.repo, &request.head)
        );
        let existing = self.call(&request.repo, Method::Get, &path, None)?;
        existing
            .as_array()
            .and_then(|prs| prs.first())
            .and_then(|pr| pr.get("number"))
            .and_then(|n| n.as_u64())
            .ok_or_else(|| {
                format!(
                    "GitHub neither opened nor reported a pull request for {}",
                    request.head
                )
            })
    }

    fn dump(&self) -> serde_json::Value {
        serde_json::json!({
            "backend": "github",
            "note": "Checks and PRs live on GitHub; nothing is pending locally.",
        })
    }
}
