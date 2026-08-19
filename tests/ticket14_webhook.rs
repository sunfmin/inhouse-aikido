//! Deliveries from GitHub, verified and acted on without anyone running a command.

#[allow(dead_code)]
mod common;

use common::{Ctx, TEST_URL};
use hq::domain::{FindingKind, Observation, TargetKind};
use hq::webhook::{
    handle_event, parse_event, sign, signature_matches, Event, ServeConfig, WebhookServer,
};
use hq::Hq;
use serde_json::json;

const SECRET: &str = "a-webhook-secret";

fn open(ctx: &Ctx) -> Hq {
    Hq::open(TEST_URL, &ctx.schema).expect("open hq")
}

fn secret_obs(problem: &str) -> Observation {
    Observation {
        engine: "fake".into(),
        problem_id: problem.into(),
        location_key: "src/config.js".into(),
        kind: FindingKind::Secret,
        package: None,
        manifest: None,
        fixed_version: None,
        message: "leaked key".into(),
        line: Some(7),
        scope: Default::default(),
    }
}

/// Run every queued Scan and report how many ran. A delivery only queues work;
/// this is the worker that does it.
fn drain(ctx: &Ctx) -> usize {
    hq::worker::run_pool(
        hq::worker::WorkerConfig {
            database_url: TEST_URL.into(),
            schema: ctx.schema.clone(),
            github_backend: "fake".into(),
            workers: 1,
            lease: std::time::Duration::from_secs(60),
            poll: std::time::Duration::from_millis(20),
        },
        true,
        None,
    )
}

fn enrolled(hq: &mut Hq) {
    hq.enroll(TargetKind::Github, "acme/web", "main").unwrap();
    hq.scan("acme/web", None).expect("baseline");
}

fn pr_payload(number: u64, head: &str, action: &str) -> serde_json::Value {
    json!({
        "action": action,
        "number": number,
        "pull_request": {"head": {"sha": head}, "base": {"ref": "main"}},
        "repository": {"full_name": "acme/web"}
    })
}

fn comment_payload(number: u64, body: &str, association: &str) -> serde_json::Value {
    json!({
        "action": "created",
        "issue": {"number": number, "pull_request": {"url": "https://api.github.com/..."}},
        "comment": {"body": body, "user": {"login": "dev"}, "author_association": association},
        "repository": {"full_name": "acme/web"}
    })
}

// --- signature ---------------------------------------------------------------

#[test]
fn only_a_delivery_signed_with_our_secret_is_accepted() {
    let body = br#"{"action":"opened"}"#;
    assert!(signature_matches(SECRET, body, &sign(SECRET, body)));

    assert!(!signature_matches(
        "another-secret",
        body,
        &sign(SECRET, body)
    ));
    assert!(!signature_matches(SECRET, b"tampered", &sign(SECRET, body)));
    assert!(!signature_matches(SECRET, body, ""), "missing header");
    assert!(
        !signature_matches(SECRET, body, "sha1=abcdef"),
        "wrong algorithm"
    );
    assert!(
        !signature_matches(SECRET, body, "sha256=nothex"),
        "malformed digest"
    );
}

// --- parsing -----------------------------------------------------------------

#[test]
fn a_pull_request_delivery_names_the_revision_to_gate() {
    let event = parse_event("pull_request", &pr_payload(42, "headsha", "opened")).unwrap();
    assert_eq!(
        event,
        Event::GatePr {
            repo: "acme/web".into(),
            number: 42,
            head: "headsha".into(),
            base: "main".into(),
        }
    );
    // A push to the PR is the same job.
    assert!(matches!(
        parse_event("pull_request", &pr_payload(42, "headsha2", "synchronize")).unwrap(),
        Event::GatePr { .. }
    ));
    // Labelling, assigning, closing are not.
    assert!(matches!(
        parse_event("pull_request", &pr_payload(42, "headsha", "labeled")).unwrap(),
        Event::Ignored(_)
    ));
}

#[test]
fn write_access_comes_from_the_author_association() {
    for association in ["OWNER", "MEMBER", "COLLABORATOR"] {
        let event = parse_event(
            "issue_comment",
            &comment_payload(1, "/hq dismiss x", association),
        )
        .unwrap();
        assert!(
            matches!(
                event,
                Event::Command {
                    can_write: true,
                    ..
                }
            ),
            "{association}"
        );
    }
    for association in ["CONTRIBUTOR", "NONE", "FIRST_TIME_CONTRIBUTOR"] {
        let event = parse_event(
            "issue_comment",
            &comment_payload(1, "/hq dismiss x", association),
        )
        .unwrap();
        assert!(
            matches!(
                event,
                Event::Command {
                    can_write: false,
                    ..
                }
            ),
            "{association}"
        );
    }
}

#[test]
fn a_comment_on_an_issue_is_not_a_comment_on_a_pr() {
    let payload = json!({
        "action": "created",
        "issue": {"number": 1},
        "comment": {"body": "/hq dismiss x", "user": {"login": "dev"}, "author_association": "OWNER"},
        "repository": {"full_name": "acme/web"}
    });
    assert!(matches!(
        parse_event("issue_comment", &payload).unwrap(),
        Event::Ignored(_)
    ));
}

#[test]
fn events_hq_has_no_opinion_about_are_acknowledged_not_errors() {
    for event in ["star", "push", "workflow_run", "ping"] {
        assert!(
            matches!(parse_event(event, &json!({})).unwrap(), Event::Ignored(_)),
            "{event} should be ignored"
        );
    }
}

// --- acting ------------------------------------------------------------------

#[test]
fn a_pull_request_delivery_gates_the_head_revision() {
    let ctx = Ctx::new();
    let mut hq = open(&ctx);
    enrolled(&mut hq);
    hq.add_fake_obs("acme/web", "headsha", secret_obs("gitleaks:aws-key"));

    let event = parse_event("pull_request", &pr_payload(42, "headsha", "opened")).unwrap();
    // The delivery queues the Scan and returns; GitHub is not kept waiting.
    let out = handle_event(&mut hq, &event, &["fake"]).unwrap();
    assert!(out.contains("queued acme/web pr=42"), "got {out}");
    hq.save().unwrap();
    assert_eq!(drain(&ctx), 1);

    let dump: serde_json::Value = serde_json::from_str(&open(&ctx).github_dump()).unwrap();
    assert_eq!(dump["checks"][0]["pr"], 42);
    assert_eq!(dump["checks"][0]["head_sha"], "headsha");
    assert_eq!(dump["checks"][0]["conclusion"], "failure");
}

#[test]
fn a_dismiss_comment_turns_the_gate_green_for_that_fingerprint() {
    let ctx = Ctx::new();
    let mut hq = open(&ctx);
    enrolled(&mut hq);
    hq.add_fake_obs("acme/web", "headsha", secret_obs("gitleaks:aws-key"));
    let gate = parse_event("pull_request", &pr_payload(42, "headsha", "opened")).unwrap();
    handle_event(&mut hq, &gate, &["fake"]).unwrap();
    hq.save().unwrap();
    drain(&ctx);

    let fingerprint = "acme/web|gitleaks:aws-key|src/config.js";
    let comment = parse_event(
        "issue_comment",
        &comment_payload(42, &format!("/hq dismiss {fingerprint}"), "MEMBER"),
    )
    .unwrap();
    let mut hq = open(&ctx);
    handle_event(&mut hq, &comment, &["fake"]).unwrap();
    hq.save().unwrap();

    let dump: serde_json::Value = serde_json::from_str(&hq.github_dump()).unwrap();
    assert_eq!(dump["checks"][0]["conclusion"], "success");
}

#[test]
fn a_commenter_who_cannot_write_the_target_is_refused() {
    let ctx = Ctx::new();
    let mut hq = open(&ctx);
    enrolled(&mut hq);
    hq.add_fake_obs("acme/web", "headsha", secret_obs("gitleaks:aws-key"));
    let gate = parse_event("pull_request", &pr_payload(42, "headsha", "opened")).unwrap();
    handle_event(&mut hq, &gate, &["fake"]).unwrap();

    let comment = parse_event(
        "issue_comment",
        &comment_payload(
            42,
            "/hq dismiss acme/web|gitleaks:aws-key|src/config.js",
            "NONE",
        ),
    )
    .unwrap();
    assert!(handle_event(&mut hq, &comment, &["fake"]).is_err());
    assert!(
        hq.dismissed_text().contains("no dismissed"),
        "the Finding stays Open"
    );
}

#[test]
fn a_comment_that_is_not_an_hq_command_is_left_alone() {
    let ctx = Ctx::new();
    let mut hq = open(&ctx);
    enrolled(&mut hq);
    let comment = parse_event(
        "issue_comment",
        &comment_payload(42, "looks good to me", "MEMBER"),
    )
    .unwrap();
    let out = handle_event(&mut hq, &comment, &["fake"]).unwrap();
    assert!(out.contains("not an HQ command"), "got {out}");
}

#[test]
fn an_event_about_a_repo_hq_does_not_track_is_a_no_op() {
    let ctx = Ctx::new();
    let mut hq = open(&ctx);
    let payload = json!({
        "action": "opened",
        "number": 1,
        "pull_request": {"head": {"sha": "x"}, "base": {"ref": "main"}},
        "repository": {"full_name": "someone/else"}
    });
    let event = parse_event("pull_request", &payload).unwrap();
    let out = handle_event(&mut hq, &event, &["fake"]).unwrap();
    assert!(out.contains("not Enrolled"), "got {out}");
}

#[test]
fn a_target_without_a_baseline_yet_is_a_no_op() {
    let ctx = Ctx::new();
    let mut hq = open(&ctx);
    hq.enroll(TargetKind::Github, "acme/web", "main").unwrap();
    let event = parse_event("pull_request", &pr_payload(1, "headsha", "opened")).unwrap();
    let out = handle_event(&mut hq, &event, &["fake"]).unwrap();
    assert!(out.contains("no Baseline"), "got {out}");
}

#[test]
fn installation_events_record_what_the_app_can_reach() {
    let ctx = Ctx::new();
    let mut hq = open(&ctx);

    let added = parse_event(
        "installation",
        &json!({
            "action": "created",
            "installation": {"id": 7},
            "repositories": [{"full_name": "acme/web"}, {"full_name": "acme/worker"}]
        }),
    )
    .unwrap();
    handle_event(&mut hq, &added, &["fake"]).unwrap();
    assert_eq!(
        hq.store.reachable_repos().unwrap(),
        vec![("acme/web".to_string(), 7), ("acme/worker".to_string(), 7)]
    );

    let removed = parse_event(
        "installation_repositories",
        &json!({
            "action": "removed",
            "installation": {"id": 7},
            "repositories_removed": [{"full_name": "acme/worker"}]
        }),
    )
    .unwrap();
    handle_event(&mut hq, &removed, &["fake"]).unwrap();
    assert_eq!(
        hq.store.reachable_repos().unwrap(),
        vec![("acme/web".to_string(), 7)]
    );
}

// --- over HTTP ---------------------------------------------------------------

fn serve(ctx: &Ctx) -> (WebhookServer, String) {
    let config = ServeConfig {
        secret: SECRET.into(),
        database_url: TEST_URL.into(),
        schema: ctx.schema.clone(),
        github_backend: "fake".into(),
        engines: vec!["fake".into()],
    };
    let server = WebhookServer::bind("127.0.0.1:0", config).expect("bind");
    let addr = format!("http://{}", server.local_addr());
    (server, addr)
}

fn deliver(
    addr: &str,
    event: &str,
    delivery: &str,
    payload: &serde_json::Value,
    secret: &str,
) -> u16 {
    let body = serde_json::to_vec(payload).unwrap();
    let res = ureq::post(addr)
        .header("X-GitHub-Event", event)
        .header("X-GitHub-Delivery", delivery)
        .header("X-Hub-Signature-256", &sign(secret, &body))
        .header("Content-Type", "application/json")
        .send(&body[..]);
    match res {
        Ok(r) => r.status().as_u16(),
        Err(ureq::Error::StatusCode(code)) => code,
        Err(e) => panic!("delivery failed: {e}"),
    }
}

#[test]
fn a_delivery_over_http_gates_the_pr_without_anyone_running_a_command() {
    let ctx = Ctx::new();
    let mut hq = open(&ctx);
    enrolled(&mut hq);
    hq.add_fake_obs("acme/web", "headsha", secret_obs("gitleaks:aws-key"));
    hq.save().unwrap();

    let (server, addr) = serve(&ctx);
    let worker = std::thread::spawn(move || server.handle_one());

    let status = deliver(
        &addr,
        "pull_request",
        "d-1",
        &pr_payload(42, "headsha", "opened"),
        SECRET,
    );
    assert_eq!(status, 202, "GitHub is answered before the Scan runs");
    let outcome = worker.join().unwrap().expect("a delivery arrived").unwrap();
    assert!(outcome.contains("queued acme/web pr=42"), "got {outcome}");
    assert_eq!(drain(&ctx), 1);

    let dump: serde_json::Value = serde_json::from_str(&open(&ctx).github_dump()).unwrap();
    assert_eq!(dump["checks"][0]["pr"], 42);
    assert_eq!(dump["checks"][0]["conclusion"], "failure");
}

#[test]
fn a_delivery_signed_with_the_wrong_secret_is_rejected_and_changes_nothing() {
    let ctx = Ctx::new();
    let mut hq = open(&ctx);
    enrolled(&mut hq);
    hq.add_fake_obs("acme/web", "headsha", secret_obs("gitleaks:aws-key"));
    hq.save().unwrap();

    let (server, addr) = serve(&ctx);
    let worker = std::thread::spawn(move || server.handle_one());

    let status = deliver(
        &addr,
        "pull_request",
        "d-2",
        &pr_payload(42, "headsha", "opened"),
        "not-our-secret",
    );
    assert_eq!(status, 401);
    let outcome = worker.join().unwrap().expect("a delivery arrived");
    assert!(outcome.is_err());

    let dump: serde_json::Value = serde_json::from_str(&open(&ctx).github_dump()).unwrap();
    assert!(
        dump["checks"].as_array().unwrap().is_empty(),
        "an unverified delivery leaves no trace"
    );
}

#[test]
fn the_same_delivery_twice_is_handled_once() {
    let ctx = Ctx::new();
    let mut hq = open(&ctx);
    enrolled(&mut hq);
    hq.save().unwrap();

    let (server, addr) = serve(&ctx);
    let worker = std::thread::spawn(move || {
        let first = server.handle_one();
        let second = server.handle_one();
        (first, second)
    });

    let payload = pr_payload(42, "headsha", "opened");
    deliver(&addr, "pull_request", "d-3", &payload, SECRET);
    deliver(&addr, "pull_request", "d-3", &payload, SECRET);

    let (first, second) = worker.join().unwrap();
    assert!(first.unwrap().unwrap().contains("queued"));
    let second = second.expect("a second delivery arrived").unwrap();
    assert!(second.contains("duplicate"), "got {second}");
}

#[test]
fn hq_refuses_to_serve_without_a_webhook_secret() {
    let ctx = Ctx::new();
    let config = ServeConfig {
        secret: String::new(),
        database_url: TEST_URL.into(),
        schema: ctx.schema.clone(),
        github_backend: "fake".into(),
        engines: vec!["fake".into()],
    };
    let err = match WebhookServer::bind("127.0.0.1:0", config) {
        Ok(_) => panic!("HQ must not serve without a webhook secret"),
        Err(e) => e,
    };
    assert!(err.contains("HQ_WEBHOOK_SECRET"), "got {err}");
}
