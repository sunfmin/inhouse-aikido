pub mod app;

use crate::domain::{CheckRun, OpenedPr, PrFile};
use serde::{Deserialize, Serialize};

/// HQ's outbound GitHub port. The backend is chosen at runtime by whoever
/// constructs `Hq`; it is never read from or written to HQ's persisted state.
pub trait Github: Send + Sync {
    /// Human-readable name of the backend, for error messages and diagnostics.
    fn backend(&self) -> &str;

    fn upsert_check(&mut self, check: CheckRun);
    fn open_pr(&mut self, repo: &str, title: &str, body: &str, files: Vec<PrFile>) -> u64;
    fn last_check(&self, repo: &str, pr: u64) -> Option<CheckRun>;

    /// What `hq github-dump` prints. A backend that talks to the real GitHub has
    /// nothing pending locally, so it says so rather than inventing an inventory.
    fn dump(&self) -> serde_json::Value;

    /// Write whatever this backend keeps locally into the Store's transaction.
    /// GitHub itself is the source of truth for a real backend, so the default
    /// is to persist nothing.
    fn persist(&self, tx: &mut postgres::Transaction<'_>) -> Result<(), String> {
        let _ = tx;
        Ok(())
    }
}

/// An in-process GitHub used by tests and local development. It keeps the checks
/// and PRs HQ would have written, in its own tables, so `hq github-dump` still
/// works across CLI invocations.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FakeGithub {
    pub checks: Vec<CheckRun>,
    pub prs: Vec<OpenedPr>,
    pub next_pr: u64,
}

impl Github for FakeGithub {
    fn backend(&self) -> &str {
        "fake"
    }

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

    fn dump(&self) -> serde_json::Value {
        serde_json::json!({
            "checks": self.checks,
            "prs": self.prs,
        })
    }

    fn persist(&self, tx: &mut postgres::Transaction<'_>) -> Result<(), String> {
        tx.batch_execute("TRUNCATE github_checks, github_prs, github_meta")
            .map_err(|e| e.to_string())?;
        for c in &self.checks {
            let ann = serde_json::to_value(&c.annotations).map_err(|e| e.to_string())?;
            tx.execute(
                "INSERT INTO github_checks (repo, pr, conclusion, summary, annotations) VALUES ($1,$2,$3,$4,$5)",
                &[&c.repo, &(c.pr as i64), &c.conclusion, &c.summary, &ann],
            )
            .map_err(|e| e.to_string())?;
        }
        for p in &self.prs {
            let files = serde_json::to_value(&p.files).map_err(|e| e.to_string())?;
            tx.execute(
                "INSERT INTO github_prs (repo, number, title, body, files) VALUES ($1,$2,$3,$4,$5)",
                &[&p.repo, &(p.number as i64), &p.title, &p.body, &files],
            )
            .map_err(|e| e.to_string())?;
        }
        tx.execute(
            "INSERT INTO github_meta (k, v) VALUES ('next_pr', $1)",
            &[&(self.next_pr as i64)],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }
}

impl FakeGithub {
    /// Read back what an earlier invocation persisted.
    pub fn load(client: &mut postgres::Client) -> Result<Self, String> {
        let mut me = Self::default();
        for row in client
            .query(
                "SELECT repo, pr, conclusion, summary, annotations FROM github_checks",
                &[],
            )
            .map_err(|e| e.to_string())?
        {
            let ann: serde_json::Value = row.get(4);
            me.checks.push(CheckRun {
                repo: row.get(0),
                pr: row.get::<_, i64>(1) as u64,
                conclusion: row.get(2),
                summary: row.get(3),
                annotations: serde_json::from_value(ann).unwrap_or_default(),
            });
        }
        for row in client
            .query(
                "SELECT repo, number, title, body, files FROM github_prs",
                &[],
            )
            .map_err(|e| e.to_string())?
        {
            let files: serde_json::Value = row.get(4);
            me.prs.push(OpenedPr {
                repo: row.get(0),
                number: row.get::<_, i64>(1) as u64,
                title: row.get(2),
                body: row.get(3),
                files: serde_json::from_value(files).unwrap_or_default(),
            });
        }
        if let Ok(row) = client.query_one("SELECT v FROM github_meta WHERE k = 'next_pr'", &[]) {
            me.next_pr = row.get::<_, i64>(0) as u64;
        }
        Ok(me)
    }
}
