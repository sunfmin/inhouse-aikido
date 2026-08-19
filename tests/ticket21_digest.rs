//! The digest: a Finding that opens on a default Revision between pull requests
//! stops being invisible.

#[allow(dead_code)]
mod common;

use common::{hq_ok, Ctx, TEST_URL};
use hq::domain::{FindingKind, Observation, Scope, Severity, TargetKind};
use hq::notify::{Notifier, Silent};
use hq::Hq;
use std::sync::{Arc, Mutex};

fn open(ctx: &Ctx) -> Hq {
    Hq::open(TEST_URL, &ctx.schema).expect("open hq")
}

fn cve(problem: &str, package: &str, severity: Severity) -> Observation {
    Observation {
        engine: "trivy".into(),
        problem_id: problem.into(),
        location_key: format!("package-lock.json::{package}"),
        kind: FindingKind::Sca,
        package: Some(package.into()),
        manifest: Some("package-lock.json".into()),
        fixed_version: None,
        message: format!("{problem} in {package}"),
        line: None,
        scope: Scope::Runtime,
        severity,
        secret: None,
        snippet: None,
    }
}

/// Remembers every digest, so a test can read what a channel would have seen.
#[derive(Default)]
struct Channel {
    posted: Arc<Mutex<Vec<String>>>,
    fail: bool,
}

impl Notifier for Channel {
    fn name(&self) -> &str {
        "channel"
    }

    fn post(&self, message: &str) -> Result<(), String> {
        if self.fail {
            return Err("slack is down".into());
        }
        self.posted.lock().unwrap().push(message.to_string());
        Ok(())
    }
}

fn channel() -> (Box<Channel>, Arc<Mutex<Vec<String>>>) {
    let posted = Arc::new(Mutex::new(Vec::new()));
    (
        Box::new(Channel {
            posted: posted.clone(),
            fail: false,
        }),
        posted,
    )
}

/// A Target with a written Baseline and nothing else going on.
fn baselined(ctx: &Ctx) -> Hq {
    let mut hq = open(ctx);
    hq.enroll(TargetKind::Github, "acme/web", "main").unwrap();
    hq.scan("acme/web", None).expect("baseline");
    hq.save().unwrap();
    hq
}

#[test]
fn a_scan_that_opens_new_findings_posts_one_digest() {
    let ctx = Ctx::new();
    let mut hq = baselined(&ctx);
    hq.add_fake_obs("acme/web", "main", cve("CVE-1", "lodash", Severity::Medium));
    hq.add_fake_obs(
        "acme/web",
        "main",
        cve("CVE-2", "minimist", Severity::Critical),
    );

    let (notifier, posted) = channel();
    let mut hq = hq.with_notifier(notifier);
    let out = hq.scan("acme/web", None).unwrap();
    hq.save().unwrap();

    assert!(out.contains("announced=2"), "{out}");
    let posted = posted.lock().unwrap().clone();
    assert_eq!(posted.len(), 1, "one digest, not one message per Finding");

    let digest = &posted[0];
    assert!(digest.contains("acme/web"), "{digest}");
    assert!(digest.contains("2 new Findings"), "{digest}");
    // Most urgent first, and each names the problem and the Fingerprint.
    let first = digest.find("CVE-2").unwrap();
    let second = digest.find("CVE-1").unwrap();
    assert!(first < second, "critical first: {digest}");
    assert!(digest.contains("severity=critical"), "{digest}");
    assert!(
        digest.contains("acme/web|CVE-2|package-lock.json::minimist"),
        "{digest}"
    );
}

#[test]
fn a_finding_is_announced_once_however_often_it_is_rescanned() {
    let ctx = Ctx::new();
    let mut hq = baselined(&ctx);
    hq.add_fake_obs("acme/web", "main", cve("CVE-1", "lodash", Severity::High));

    let (notifier, posted) = channel();
    let mut hq = hq.with_notifier(notifier);
    hq.scan("acme/web", None).unwrap();
    hq.save().unwrap();
    assert_eq!(posted.lock().unwrap().len(), 1);

    // The same CVE is still there on the next re-scan. Nobody needs telling
    // again.
    let (notifier, posted_again) = channel();
    let mut hq = open(&ctx).with_notifier(notifier);
    hq.add_fake_obs("acme/web", "main", cve("CVE-1", "lodash", Severity::High));
    let out = hq.scan("acme/web", None).unwrap();
    hq.save().unwrap();
    assert!(!out.contains("announced"), "{out}");
    assert!(posted_again.lock().unwrap().is_empty());

    // A genuinely new one is announced, and only it.
    let (notifier, posted_new) = channel();
    let mut hq = open(&ctx).with_notifier(notifier);
    hq.add_fake_obs("acme/web", "main", cve("CVE-1", "lodash", Severity::High));
    hq.add_fake_obs("acme/web", "main", cve("CVE-9", "ms", Severity::Low));
    hq.scan("acme/web", None).unwrap();
    hq.save().unwrap();
    let digest = posted_new.lock().unwrap().clone();
    assert_eq!(digest.len(), 1);
    assert!(digest[0].contains("1 new Finding"), "{}", digest[0]);
    assert!(digest[0].contains("CVE-9"), "{}", digest[0]);
    assert!(!digest[0].contains("CVE-1"), "{}", digest[0]);
}

#[test]
fn a_dismissed_finding_is_never_announced() {
    let ctx = Ctx::new();
    let mut hq = baselined(&ctx);
    hq.add_fake_obs("acme/web", "main", cve("CVE-1", "lodash", Severity::High));
    hq.scan("acme/web", None).unwrap();
    hq.save().unwrap();

    // Announced by nobody so far — there was no notifier. Dismiss it, then run
    // a Scan that would otherwise announce it.
    hq_ok(
        &ctx,
        &["dismiss", "acme/web|CVE-1|package-lock.json::lodash"],
    );

    let (notifier, posted) = channel();
    let mut hq = open(&ctx).with_notifier(notifier);
    hq.add_fake_obs("acme/web", "main", cve("CVE-1", "lodash", Severity::High));
    hq.scan("acme/web", None).unwrap();
    hq.save().unwrap();
    assert!(posted.lock().unwrap().is_empty(), "a Dismissed Finding");

    // Nor is one that got Fixed: it is not Open, so it is not news.
    let (notifier, posted) = channel();
    let mut hq = open(&ctx).with_notifier(notifier);
    hq.scan("acme/web", None).unwrap();
    hq.save().unwrap();
    assert!(posted.lock().unwrap().is_empty());
}

#[test]
fn a_pull_request_scan_announces_nothing() {
    let ctx = Ctx::new();
    let mut hq = baselined(&ctx);
    hq.add_fake_obs("acme/web", "head", cve("CVE-1", "lodash", Severity::High));

    let (notifier, posted) = channel();
    let mut hq = hq.with_notifier(notifier);
    hq.handle_pr("acme/web", 42, "head", "main").unwrap();
    hq.save().unwrap();

    // The Gate already told the Developer. The digest is for the Findings
    // nobody has a pull request open for.
    assert!(posted.lock().unwrap().is_empty());
}

#[test]
fn slack_being_down_does_not_fail_the_scan_and_the_finding_is_still_news() {
    let ctx = Ctx::new();
    let mut hq = baselined(&ctx);
    hq.add_fake_obs("acme/web", "main", cve("CVE-1", "lodash", Severity::High));

    let mut hq = hq.with_notifier(Box::new(Channel {
        fail: true,
        ..Default::default()
    }));
    let out = hq.scan("acme/web", None).expect("the Scan survives");
    hq.save().unwrap();
    assert!(out.contains("observations=1"), "{out}");
    assert!(!out.contains("announced"), "{out}");

    // Nothing was marked announced, so the next Scan says it instead.
    let (notifier, posted) = channel();
    let mut hq = open(&ctx).with_notifier(notifier);
    hq.add_fake_obs("acme/web", "main", cve("CVE-1", "lodash", Severity::High));
    hq.scan("acme/web", None).unwrap();
    hq.save().unwrap();
    assert_eq!(posted.lock().unwrap().len(), 1);
}

#[test]
fn with_no_webhook_configured_nothing_changes() {
    let ctx = Ctx::new();
    let mut hq = baselined(&ctx);
    hq.add_fake_obs("acme/web", "main", cve("CVE-1", "lodash", Severity::High));

    assert!(!Silent.enabled());
    let out = hq.scan("acme/web", None).unwrap();
    hq.save().unwrap();
    assert!(!out.contains("announced"), "{out}");
    assert!(hq_ok(&ctx, &["findings"]).contains("CVE-1"));
}

#[test]
fn baseline_day_announces_nothing() {
    let ctx = Ctx::new();
    let mut hq = open(&ctx);
    hq.enroll(TargetKind::Github, "acme/web", "main").unwrap();
    hq.add_fake_obs("acme/web", "main", cve("CVE-1", "lodash", Severity::High));

    let (notifier, posted) = channel();
    let mut hq = hq.with_notifier(notifier);
    hq.scan("acme/web", None).unwrap();
    hq.save().unwrap();

    // Everything is new on the first Scan. Announcing all of it is noise, not
    // news.
    assert!(posted.lock().unwrap().is_empty());
}

/// A Slack incoming webhook, as far as HQ can tell.
#[test]
fn the_slack_notifier_posts_json_text_to_the_webhook() {
    let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").expect("bind"));
    let url = format!(
        "http://{}/services/T/B/xxx",
        server.server_addr().to_ip().unwrap()
    );
    let seen: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let listener = {
        let server = server.clone();
        let seen = seen.clone();
        std::thread::spawn(move || {
            if let Ok(mut request) = server.recv() {
                let mut body = String::new();
                let _ = std::io::Read::read_to_string(request.as_reader(), &mut body);
                seen.lock()
                    .unwrap()
                    .push((request.method().as_str().to_string(), body));
                let _ = request.respond(tiny_http::Response::from_string("ok"));
            }
        })
    };

    hq::notify::SlackWebhook::new(&url)
        .post("*acme/web* — 1 new Finding")
        .expect("posted");
    listener.join().unwrap();

    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, "POST");
    let body: serde_json::Value = serde_json::from_str(&seen[0].1).unwrap();
    assert_eq!(body["text"], "*acme/web* — 1 new Finding");
}
