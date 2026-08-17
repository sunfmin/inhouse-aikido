use crate::domain::{CheckRun, OpenedPr, PrFile};
use serde::{Deserialize, Serialize};

pub trait Github: Send + Sync {
    fn upsert_check(&mut self, check: CheckRun);
    fn open_pr(&mut self, repo: &str, title: &str, body: &str, files: Vec<PrFile>) -> u64;
    fn last_check(&self, repo: &str, pr: u64) -> Option<CheckRun>;
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FakeGithub {
    pub checks: Vec<CheckRun>,
    pub prs: Vec<OpenedPr>,
    pub next_pr: u64,
}

impl FakeGithub {
    pub fn dump(&self) -> serde_json::Value {
        serde_json::json!({
            "checks": self.checks,
            "prs": self.prs,
        })
    }
}

impl Github for FakeGithub {
    fn upsert_check(&mut self, check: CheckRun) {
        self.checks
            .retain(|c| !(c.repo == check.repo && c.pr == check.pr));
        self.checks.push(check);
    }

    fn open_pr(&mut self, repo: &str, title: &str, body: &str, files: Vec<PrFile>) -> u64 {
        self.next_pr += 1;
        let number = self.next_pr;
        self.prs.push(OpenedPr {
            repo: repo.to_string(),
            number,
            title: title.to_string(),
            body: body.to_string(),
            files,
        });
        number
    }

    fn last_check(&self, repo: &str, pr: u64) -> Option<CheckRun> {
        self.checks
            .iter()
            .rev()
            .find(|c| c.repo == repo && c.pr == pr)
            .cloned()
    }
}
