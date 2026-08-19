#[allow(dead_code)]
mod common;

use common::{Ctx, TEST_URL};
use hq::domain::{CheckRun, PrRequest};
use hq::github::Github;
use hq::Hq;
use std::sync::{Arc, Mutex};

/// A backend that is not the fake one, standing in for a real GitHub.
/// Like a real backend it keeps nothing in HQ's persisted state.
#[derive(Default)]
struct Recorder {
    checks: Arc<Mutex<Vec<CheckRun>>>,
}

impl Github for Recorder {
    fn backend(&self) -> &str {
        "recorder"
    }
    fn upsert_check(&mut self, check: CheckRun) -> Result<(), String> {
        self.checks.lock().unwrap().push(check);
        Ok(())
    }
    fn open_pr(&mut self, _request: PrRequest) -> Result<u64, String> {
        Ok(1)
    }
    fn dump(&self) -> serde_json::Value {
        serde_json::json!({ "backend": "recorder" })
    }
}

#[test]
fn gate_goes_to_the_backend_hq_was_opened_with() {
    let ctx = Ctx::new();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut hq = Hq::open_with_github(
        TEST_URL,
        &ctx.schema,
        Box::new(Recorder {
            checks: seen.clone(),
        }),
    )
    .expect("open hq on the recorder backend");

    assert_eq!(hq.github.backend(), "recorder");

    hq.enroll(hq::domain::TargetKind::Github, "acme/web", "main")
        .unwrap();
    hq.scan("acme/web", None).unwrap();
    hq.handle_pr("acme/web", 7, "headsha", "main").unwrap();

    let checks = seen.lock().unwrap();
    assert_eq!(checks.len(), 1, "the Gate wrote to the chosen backend");
    assert_eq!(checks[0].repo, "acme/web");
    assert_eq!(checks[0].pr, 7);
    assert_eq!(checks[0].conclusion, "success");
    drop(checks);

    // A backend that is not the fake one leaves nothing behind in HQ's state.
    hq.save().unwrap();
    let reopened = Hq::open(TEST_URL, &ctx.schema).expect("reopen on the fake backend");
    let dump: serde_json::Value = serde_json::from_str(&reopened.github_dump()).unwrap();
    assert_eq!(dump["checks"].as_array().unwrap().len(), 0);
    assert_eq!(dump["prs"].as_array().unwrap().len(), 0);
}

#[test]
fn fake_backend_still_survives_across_invocations() {
    let ctx = Ctx::new();
    let mut hq = Hq::open(TEST_URL, &ctx.schema).unwrap();
    assert_eq!(hq.github.backend(), "fake");

    hq.enroll(hq::domain::TargetKind::Github, "acme/web", "main")
        .unwrap();
    hq.scan("acme/web", None).unwrap();
    hq.handle_pr("acme/web", 3, "headsha", "main").unwrap();
    hq.save().unwrap();

    let reopened = Hq::open(TEST_URL, &ctx.schema).unwrap();
    let dump: serde_json::Value = serde_json::from_str(&reopened.github_dump()).unwrap();
    let checks = dump["checks"].as_array().unwrap();
    assert_eq!(checks.len(), 1);
    assert_eq!(checks[0]["pr"], 3);
    assert_eq!(checks[0]["conclusion"], "success");
}
