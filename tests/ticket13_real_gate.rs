//! The Gate a Developer actually sees: a Check Run on the PR's head Revision.
//!
//! HQ runs against a stub GitHub on localhost. Nothing here reaches the network.

#[allow(dead_code)]
mod common;

use common::ghstub::{GithubStub, StubOptions};
use common::{Ctx, TEST_URL};
use hq::domain::{FindingKind, Observation, TargetKind};
use hq::github::app::{AppAuth, AppConfig};
use hq::github::real::RealGithub;
use hq::Hq;

const KEY: &str = include_str!("fixtures/app/test-app-key.pem");

fn hq_on(stub: &GithubStub, ctx: &Ctx) -> Hq {
    let auth = std::sync::Arc::new(std::sync::Mutex::new(AppAuth::new(AppConfig::new(
        "42",
        KEY,
        stub.base.clone(),
    ))));
    Hq::open_with_github(TEST_URL, &ctx.schema, Box::new(RealGithub::new(auth)))
        .expect("open HQ on the real GitHub backend")
}

fn obs(problem: &str, location: &str, kind: FindingKind, line: Option<u32>) -> Observation {
    Observation {
        engine: "fake".into(),
        problem_id: problem.into(),
        location_key: location.into(),
        kind,
        package: None,
        manifest: None,
        fixed_version: None,
        message: format!("{problem} at {location}"),
        line,
    }
}

/// Enroll, write the Baseline from `main`, and return HQ ready to Gate a PR.
fn enrolled(hq: &mut Hq, baseline: Vec<Observation>) {
    hq.enroll(TargetKind::Github, "acme/web", "main").unwrap();
    for o in baseline {
        hq.add_fake_obs("acme/web", "main", o);
    }
    hq.scan("acme/web", None).expect("baseline scan");
}

fn check_payload(stub: &GithubStub) -> serde_json::Value {
    let posts = stub.calls_to("POST", "/check-runs");
    let patches = stub.calls_to("PATCH", "/check-runs/");
    posts
        .last()
        .or_else(|| patches.last())
        .map(|c| c.body.clone())
        .expect("HQ wrote a Check Run")
}

#[test]
fn a_clean_pr_gets_a_successful_check_run_on_the_head_revision() {
    let ctx = Ctx::new();
    let stub = GithubStub::start();
    let mut hq = hq_on(&stub, &ctx);
    enrolled(&mut hq, vec![]);

    hq.handle_pr("acme/web", 11, "headsha1", "main").unwrap();

    let body = check_payload(&stub);
    assert_eq!(body["name"], "hq");
    assert_eq!(body["head_sha"], "headsha1");
    assert_eq!(body["status"], "completed");
    assert_eq!(body["conclusion"], "success");

    // The App's own token, not a person's.
    assert!(stub
        .authorization_for("/check-runs")
        .starts_with("token ghs_installation_"));
}

#[test]
fn a_new_finding_fails_the_gate_and_annotates_the_file_it_is_in() {
    let ctx = Ctx::new();
    let stub = GithubStub::start();
    let mut hq = hq_on(&stub, &ctx);
    enrolled(&mut hq, vec![]);

    hq.add_fake_obs(
        "acme/web",
        "headsha2",
        obs("gitleaks:aws-key", "src/config.js", FindingKind::Secret, Some(42)),
    );
    hq.handle_pr("acme/web", 12, "headsha2", "main").unwrap();

    let body = check_payload(&stub);
    assert_eq!(body["conclusion"], "failure");
    assert!(
        body["output"]["summary"]
            .as_str()
            .unwrap()
            .contains("gitleaks:aws-key"),
        "the summary names what blocked the merge: {}",
        body["output"]["summary"]
    );

    let annotations = body["output"]["annotations"].as_array().unwrap();
    assert_eq!(annotations.len(), 1);
    let a = &annotations[0];
    assert_eq!(a["path"], "src/config.js");
    assert_eq!(a["start_line"], 42);
    assert_eq!(a["end_line"], 42);
    assert_eq!(a["annotation_level"], "failure");
    // A Developer can act on the annotation without leaving the PR.
    assert!(a["message"].as_str().unwrap().contains("/hq dismiss"));
}

#[test]
fn a_dependency_finding_annotates_the_manifest_not_a_package_name() {
    let ctx = Ctx::new();
    let stub = GithubStub::start();
    let mut hq = hq_on(&stub, &ctx);
    enrolled(&mut hq, vec![]);

    hq.add_fake_obs(
        "acme/web",
        "headsha3",
        obs(
            "CVE-2024-0001",
            "web/package-lock.json::lodash",
            FindingKind::Sca,
            None,
        ),
    );
    hq.handle_pr("acme/web", 13, "headsha3", "main").unwrap();

    let body = check_payload(&stub);
    let a = &body["output"]["annotations"][0];
    assert_eq!(a["path"], "web/package-lock.json");
    assert_eq!(a["start_line"], 1);
}

#[test]
fn baseline_debt_is_annotated_as_a_warning_and_does_not_block() {
    let ctx = Ctx::new();
    let stub = GithubStub::start();
    let mut hq = hq_on(&stub, &ctx);
    let old = obs("CVE-2020-9999", "api/go.sum::grpc", FindingKind::Sca, None);
    enrolled(&mut hq, vec![old.clone()]);

    hq.add_fake_obs("acme/web", "headsha4", old);
    hq.handle_pr("acme/web", 14, "headsha4", "main").unwrap();

    let body = check_payload(&stub);
    assert_eq!(body["conclusion"], "success", "old debt does not block");
    let annotations = body["output"]["annotations"].as_array().unwrap();
    assert_eq!(annotations.len(), 1, "but it is still visible");
    assert_eq!(annotations[0]["annotation_level"], "warning");
}

#[test]
fn scanning_the_same_revision_again_updates_the_same_check_run() {
    let ctx = Ctx::new();
    let stub = GithubStub::start();
    let mut hq = hq_on(&stub, &ctx);
    enrolled(&mut hq, vec![]);

    hq.handle_pr("acme/web", 15, "headsha5", "main").unwrap();
    hq.handle_pr("acme/web", 15, "headsha5", "main").unwrap();

    assert_eq!(
        stub.calls_to("POST", "/check-runs").len(),
        1,
        "one Check Run per Revision, not one per Scan"
    );
    assert_eq!(stub.calls_to("PATCH", "/check-runs/").len(), 1);
}

#[test]
fn engines_that_fail_fail_the_gate_closed() {
    let ctx = Ctx::new();
    let stub = GithubStub::start();
    let mut hq = hq_on(&stub, &ctx);
    enrolled(&mut hq, vec![]);

    hq.add_fake_fail("acme/web", "headsha6");
    hq.handle_pr("acme/web", 16, "headsha6", "main").unwrap();

    let body = check_payload(&stub);
    assert_eq!(body["conclusion"], "failure");
    assert!(body["output"]["summary"]
        .as_str()
        .unwrap()
        .contains("engines failed"));
}

#[test]
fn more_annotations_than_one_request_allows_are_batched_not_dropped() {
    let ctx = Ctx::new();
    let stub = GithubStub::start();
    let mut hq = hq_on(&stub, &ctx);
    enrolled(&mut hq, vec![]);

    for i in 0..60 {
        hq.add_fake_obs(
            "acme/web",
            "headsha7",
            obs(
                &format!("RULE-{i:03}"),
                &format!("src/file{i:03}.js"),
                FindingKind::Sast,
                Some(i + 1),
            ),
        );
    }
    hq.handle_pr("acme/web", 17, "headsha7", "main").unwrap();

    let posted = stub.calls_to("POST", "/check-runs");
    let patched = stub.calls_to("PATCH", "/check-runs/");
    assert_eq!(posted.len(), 1);
    assert_eq!(patched.len(), 1, "the remainder goes up as an update");

    let first = posted[0].body["output"]["annotations"].as_array().unwrap().len();
    let rest = patched[0].body["output"]["annotations"].as_array().unwrap().len();
    assert_eq!(first, 50, "GitHub takes 50 annotations per request");
    assert_eq!(first + rest, 60, "every Finding is annotated");
}

#[test]
fn a_gate_that_cannot_be_written_is_an_error_not_a_silent_pass() {
    let ctx = Ctx::new();
    let stub = GithubStub::with(StubOptions {
        reject_check_writes: true,
        ..StubOptions::default()
    });
    let mut hq = hq_on(&stub, &ctx);
    enrolled(&mut hq, vec![]);

    let err = hq
        .handle_pr("acme/web", 18, "headsha8", "main")
        .expect_err("a Check Run HQ could not write must not look like a pass");
    assert!(err.contains("500"), "got {err:?}");
}
