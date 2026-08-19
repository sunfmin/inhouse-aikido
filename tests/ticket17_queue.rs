//! The Scan queue: a delivery queues work, workers run it, and an Operator can
//! see what happened.

#[allow(dead_code)]
mod common;

use common::{hq_ok, Ctx, TEST_URL};
use hq::domain::TargetKind;
use hq::engine::{run_with_timeout, EngineError};
use hq::queue::{JobRequest, Purpose, Queue};
use hq::webhook::{handle_event, parse_event};
use hq::worker::{run_pool, WorkerConfig};
use hq::Hq;
use serde_json::json;
use std::time::Duration;

fn open(ctx: &Ctx) -> Hq {
    Hq::open(TEST_URL, &ctx.schema).expect("open hq")
}

fn queue(ctx: &Ctx) -> Queue {
    Queue::new(TEST_URL, &ctx.schema)
}

fn config(ctx: &Ctx, workers: usize) -> WorkerConfig {
    WorkerConfig {
        database_url: TEST_URL.into(),
        schema: ctx.schema.clone(),
        github_backend: "fake".into(),
        intel_backend: "fake".into(),
        workers,
        lease: Duration::from_secs(60),
        poll: Duration::from_millis(20),
    }
}

fn enrolled(hq: &mut Hq, name: &str) {
    hq.enroll(TargetKind::Github, name, "main").unwrap();
    hq.scan(name, None).expect("baseline");
}

fn job(target: &str, revision: &str) -> JobRequest {
    JobRequest {
        target: target.into(),
        revision: revision.into(),
        engines: vec!["fake".into()],
        purpose: Purpose::Default,
        pr_number: None,
        base_revision: None,
    }
}

#[test]
fn a_pull_request_delivery_returns_before_any_engine_runs() {
    let ctx = Ctx::new();
    let mut hq = open(&ctx);
    enrolled(&mut hq, "acme/web");
    hq.save().unwrap();

    let event = parse_event(
        "pull_request",
        &json!({
            "action": "opened",
            "number": 42,
            "pull_request": {"head": {"sha": "headsha"}, "base": {"ref": "main"}},
            "repository": {"full_name": "acme/web"}
        }),
    )
    .unwrap();
    let out = handle_event(&mut hq, &event, &["fake"]).unwrap();
    hq.save().unwrap();

    assert!(out.contains("queued"), "got {out}");
    // Nothing has been gated yet — the Scan is still waiting for a worker.
    let dump: serde_json::Value = serde_json::from_str(&open(&ctx).github_dump()).unwrap();
    assert!(dump["checks"].as_array().unwrap().is_empty(), "{dump}");

    let scans = hq_ok(&ctx, &["scans"]);
    assert!(scans.contains("gate acme/web@headsha"), "{scans}");
    assert!(scans.contains("state=queued"), "{scans}");
}

#[test]
fn two_workers_never_run_the_same_scan() {
    let ctx = Ctx::new();
    let hq = open(&ctx);
    hq.save().unwrap();
    let queue = queue(&ctx);
    for n in 0..24 {
        queue
            .enqueue(&job(&format!("acme/repo{n}"), "main"))
            .unwrap();
    }

    let claimed: Vec<i64> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..6)
            .map(|w| {
                let queue = Queue::new(TEST_URL, &ctx.schema);
                scope.spawn(move || {
                    let name = format!("w{w}");
                    let mut mine = Vec::new();
                    while let Ok(Some(job)) = queue.claim(&name) {
                        mine.push(job.id);
                    }
                    mine
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect()
    });

    assert_eq!(claimed.len(), 24, "every job was claimed exactly once");
    let mut sorted = claimed.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), 24, "a job was claimed twice: {claimed:?}");
}

#[test]
fn a_worker_pool_runs_at_most_the_configured_number_of_scans() {
    let ctx = Ctx::new();
    let mut hq = open(&ctx);
    for n in 0..9 {
        enrolled(&mut hq, &format!("acme/repo{n}"));
    }
    hq.save().unwrap();
    let queue = queue(&ctx);
    for n in 0..9 {
        queue
            .enqueue(&job(&format!("acme/repo{n}"), "main"))
            .unwrap();
    }

    assert_eq!(run_pool(config(&ctx, 3), true, None), 9);
    let workers: std::collections::HashSet<String> = queue
        .list(50)
        .unwrap()
        .into_iter()
        .filter_map(|r| r.claimed_by)
        .collect();
    assert!(
        workers.len() <= 3,
        "at most 3 Scans ran at once, saw {workers:?}"
    );
    assert_eq!(queue.pending().unwrap(), 0);
}

#[test]
fn a_job_whose_worker_died_becomes_claimable_again() {
    let ctx = Ctx::new();
    let hq = open(&ctx);
    hq.save().unwrap();
    let queue = queue(&ctx);
    let id = queue.enqueue(&job("acme/web", "main")).unwrap();
    let claimed = queue.claim("doomed").unwrap().expect("a job to claim");
    assert_eq!(claimed.id, id);
    assert!(queue.claim("healthy").unwrap().is_none(), "still held");

    // The worker stops reporting: no heartbeat for longer than the lease.
    let mut client = postgres::Client::connect(TEST_URL, postgres::NoTls).unwrap();
    client
        .batch_execute(&format!(
            "SET search_path TO {}; UPDATE scan_jobs SET heartbeat = now() - interval '1 hour'",
            ctx.schema
        ))
        .unwrap();

    assert_eq!(queue.requeue_stale(Duration::from_secs(60)).unwrap(), 1);
    let retaken = queue.claim("healthy").unwrap().expect("reclaimable");
    assert_eq!(retaken.id, id, "the same Scan, now somebody else's");
}

#[test]
fn a_scan_queued_for_a_target_that_gets_unenrolled_is_discarded() {
    let ctx = Ctx::new();
    let mut hq = open(&ctx);
    enrolled(&mut hq, "acme/web");
    hq.save().unwrap();
    queue(&ctx).enqueue(&job("acme/web", "main")).unwrap();

    let mut hq = open(&ctx);
    hq.unenroll("acme/web").unwrap();
    hq.save().unwrap();

    assert_eq!(run_pool(config(&ctx, 1), true, None), 1);
    let scans = hq_ok(&ctx, &["scans"]);
    assert!(scans.contains("state=discarded"), "{scans}");
    assert!(scans.contains("not Enrolled"), "{scans}");
}

#[test]
fn a_failed_engine_fails_the_gate_closed() {
    let ctx = Ctx::new();
    hq_ok(
        &ctx,
        &["enroll", "github", "acme/web", "--revision", "main"],
    );
    hq_ok(&ctx, &["scan", "acme/web"]);
    hq_ok(&ctx, &["fake-fail", "acme/web", "headsha"]);
    queue(&ctx)
        .enqueue(&JobRequest {
            target: "acme/web".into(),
            revision: "headsha".into(),
            engines: vec!["fake".into()],
            purpose: Purpose::Gate,
            pr_number: Some(42),
            base_revision: Some("main".into()),
        })
        .unwrap();

    assert_eq!(run_pool(config(&ctx, 1), true, None), 1);
    let dump: serde_json::Value = serde_json::from_str(&hq_ok(&ctx, &["github-dump"])).unwrap();
    assert_eq!(dump["checks"][0]["conclusion"], "failure");
    assert_eq!(dump["checks"][0]["summary"], "engines failed");
}

#[test]
fn an_engine_that_hangs_is_a_failed_engine_not_a_scan_that_never_ends() {
    let mut command = std::process::Command::new("sleep");
    command.arg("30");
    let started = std::time::Instant::now();
    let err = run_with_timeout(command, "sleepy", Duration::from_millis(300)).unwrap_err();

    assert!(
        matches!(err, EngineError::TimedOut(ref e) if e == "sleepy"),
        "{err}"
    );
    // A failed Engine by any other name: the Scan reports it and the Gate fails.
    assert_eq!(err.engine(), "sleepy");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the Engine was killed, not waited on"
    );
}

#[test]
fn scans_reports_target_revision_engines_and_timing() {
    let ctx = Ctx::new();
    let mut hq = open(&ctx);
    enrolled(&mut hq, "acme/web");
    hq.save().unwrap();
    queue(&ctx).enqueue(&job("acme/web", "main")).unwrap();

    assert_eq!(hq_ok(&ctx, &["scans"]).lines().count(), 1);
    run_pool(config(&ctx, 1), true, None);

    let scans = hq_ok(&ctx, &["scans"]);
    assert!(scans.contains("default acme/web@main"), "{scans}");
    assert!(scans.contains("engines=fake"), "{scans}");
    assert!(scans.contains("state=done"), "{scans}");
    assert!(scans.contains("took="), "{scans}");
    assert!(scans.contains("waited="), "{scans}");
}

#[test]
fn intel_rescan_queues_one_scan_per_target() {
    let ctx = Ctx::new();
    let mut hq = open(&ctx);
    enrolled(&mut hq, "acme/web");
    enrolled(&mut hq, "acme/worker");
    hq.save().unwrap();

    let out = hq_ok(&ctx, &["intel-rescan"]);
    assert_eq!(out.lines().count(), 2, "{out}");
    assert_eq!(queue(&ctx).pending().unwrap(), 2);

    // Asking twice while the first Scans still wait does not queue them twice.
    hq_ok(&ctx, &["intel-rescan"]);
    assert_eq!(queue(&ctx).pending().unwrap(), 2);

    assert_eq!(run_pool(config(&ctx, 2), true, None), 2);
    assert_eq!(queue(&ctx).pending().unwrap(), 0);
}

#[test]
fn no_scans_yet_says_so() {
    let ctx = Ctx::new();
    assert_eq!(hq_ok(&ctx, &["scans"]), "no scans");
}
