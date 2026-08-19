//! The GitHub backend that actually writes to GitHub.
//!
//! HQ's Gate is a Check Run on the PR's head Revision, named `hq`. There is one
//! per Revision: a second Scan of the same Revision updates it rather than
//! stacking another. Annotations go up in the batches the API accepts.

use crate::domain::{Annotation, CheckRun, PrFile};
use crate::github::app::{AppAuth, Method};
use crate::github::Github;

/// The Check Run's name on GitHub. A Developer looks for this in the checks list.
pub const CHECK_NAME: &str = "hq";
/// GitHub accepts at most this many annotations per request.
const ANNOTATION_BATCH: usize = 50;
/// GitHub truncates a longer annotation title.
const TITLE_LIMIT: usize = 255;

pub struct RealGithub {
    auth: AppAuth,
}

impl RealGithub {
    pub fn new(auth: AppAuth) -> Self {
        Self { auth }
    }

    pub fn from_env() -> Result<Self, String> {
        Ok(Self::new(AppAuth::from_env()?))
    }

    /// The id of the Check Run HQ already wrote for this Revision, if any.
    fn existing_check(&mut self, repo: &str, head_sha: &str) -> Result<Option<u64>, String> {
        let path = format!("/repos/{repo}/commits/{head_sha}/check-runs?check_name={CHECK_NAME}");
        let body = self.auth.call_for_repo(repo, Method::Get, &path, None)?;
        Ok(body
            .get("check_runs")
            .and_then(|r| r.as_array())
            .and_then(|runs| runs.first())
            .and_then(|run| run.get("id"))
            .and_then(|id| id.as_u64()))
    }
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
                self.auth
                    .call_for_repo(&check.repo, Method::Patch, &path, Some(payload))?;
                id
            }
            None => {
                let path = format!("/repos/{}/check-runs", check.repo);
                let created =
                    self.auth
                        .call_for_repo(&check.repo, Method::Post, &path, Some(payload))?;
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
            self.auth
                .call_for_repo(&check.repo, Method::Patch, &path, Some(payload))?;
        }
        Ok(())
    }

    fn open_pr(
        &mut self,
        repo: &str,
        _title: &str,
        _body: &str,
        _files: Vec<PrFile>,
    ) -> Result<u64, String> {
        Err(format!(
            "HQ cannot yet open a Remediation on {repo} against real GitHub"
        ))
    }

    fn can_open_pr(&self) -> bool {
        false
    }

    fn dump(&self) -> serde_json::Value {
        serde_json::json!({
            "backend": "github",
            "note": "Checks and PRs live on GitHub; nothing is pending locally.",
        })
    }
}
