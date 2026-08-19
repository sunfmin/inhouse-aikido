//! Secret validity: a dead credential stops being treated like a live incident,
//! and a live one stops being treated like debt.

#[allow(dead_code)]
mod common;

use common::{hq_ok, Ctx, TEST_URL};
use hq::domain::{FindingKind, LeakedSecret, Observation, Scope, Severity, Validity};
use hq::verify::{NoVerification, ProviderEndpoints, ProviderVerifier, SecretVerifier};
use hq::Hq;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

fn open(ctx: &Ctx) -> Hq {
    Hq::open(TEST_URL, &ctx.schema).expect("open hq")
}

fn leaked(problem: &str, file: &str, value: &str) -> Observation {
    Observation {
        engine: "gitleaks".into(),
        problem_id: problem.into(),
        location_key: file.into(),
        kind: FindingKind::Secret,
        package: None,
        manifest: None,
        fixed_version: None,
        message: "credential in the tree".into(),
        line: Some(3),
        scope: Scope::Unknown,
        severity: Severity::High,
        secret: Some(LeakedSecret::new(value)),
        snippet: None,
    }
}

/// A verifier that answers from a table, and counts what it was asked.
struct Scripted {
    verdicts: Vec<(&'static str, Validity)>,
    asked: Arc<Mutex<Vec<String>>>,
}

impl SecretVerifier for Scripted {
    fn name(&self) -> &str {
        "scripted"
    }

    fn check(&self, _rule: &str, value: &str) -> Validity {
        self.asked.lock().unwrap().push(value.to_string());
        self.verdicts
            .iter()
            .find(|(v, _)| *v == value)
            .map(|(_, verdict)| *verdict)
            .unwrap_or(Validity::Unverified)
    }
}

fn scripted(verdicts: Vec<(&'static str, Validity)>) -> (Box<Scripted>, Arc<Mutex<Vec<String>>>) {
    let asked = Arc::new(Mutex::new(Vec::new()));
    (
        Box::new(Scripted {
            verdicts,
            asked: asked.clone(),
        }),
        asked,
    )
}

// --- the verdict --------------------------------------------------------------

#[test]
fn a_secret_finding_carries_active_inactive_or_unverified() {
    let ctx = Ctx::new();
    let mut hq = open(&ctx);
    hq.enroll(hq::domain::TargetKind::Github, "acme/web", "main")
        .unwrap();
    hq.scan("acme/web", None).unwrap();
    hq.add_fake_obs("acme/web", "head", leaked("aws-key", "a.js", "live-one"));
    hq.add_fake_obs("acme/web", "head", leaked("npm-token", "b.js", "dead-one"));
    hq.add_fake_obs(
        "acme/web",
        "head",
        leaked("odd-rule", "c.js", "unknown-shape"),
    );

    let (verifier, asked) = scripted(vec![
        ("live-one", Validity::Active),
        ("dead-one", Validity::Inactive),
    ]);
    let mut hq = hq.with_verifier(verifier);
    hq.scan("acme/web", Some("head")).unwrap();
    hq.save().unwrap();

    assert_eq!(
        asked.lock().unwrap().len(),
        3,
        "every credential asked about"
    );
    let listing = hq_ok(&ctx, &["findings"]);
    assert!(listing.contains("aws-key|a.js state=Open"), "{listing}");
    for (rule, verdict) in [
        ("aws-key", "active"),
        ("npm-token", "inactive"),
        ("odd-rule", "unverified"),
    ] {
        let line = listing
            .lines()
            .find(|l| l.contains(rule))
            .unwrap_or_else(|| panic!("no line for {rule} in {listing}"));
        assert!(line.contains(&format!("validity={verdict}")), "{line}");
    }
}

#[test]
fn the_credential_itself_is_never_stored_or_printed() {
    let ctx = Ctx::new();
    let mut hq = open(&ctx);
    hq.enroll(hq::domain::TargetKind::Github, "acme/web", "main")
        .unwrap();
    hq.scan("acme/web", None).unwrap();
    hq.add_fake_obs(
        "acme/web",
        "head",
        leaked("aws-key", "a.js", "ghp_supersecretvalue"),
    );
    let (verifier, _) = scripted(vec![("ghp_supersecretvalue", Validity::Active)]);
    let mut hq = hq.with_verifier(verifier);
    hq.scan("acme/web", Some("head")).unwrap();
    hq.save().unwrap();

    // Nothing HQ writes or shows carries the value.
    for surface in [
        hq_ok(&ctx, &["findings"]),
        hq_ok(&ctx, &["findings", "--json"]),
        hq_ok(&ctx, &["github-dump"]),
        hq_ok(&ctx, &["brief"]),
    ] {
        assert!(
            !surface.contains("ghp_supersecretvalue"),
            "a credential leaked into HQ's own output: {surface}"
        );
    }
    // Not in the database either.
    let mut client = postgres::Client::connect(TEST_URL, postgres::NoTls).unwrap();
    client
        .batch_execute(&format!("SET search_path TO {}", ctx.schema))
        .unwrap();
    for table in ["observations", "findings", "fake_obs"] {
        let row = client
            .query_one(
                &format!("SELECT count(*) FROM {table} WHERE {table}::text LIKE '%supersecret%'"),
                &[],
            )
            .unwrap();
        assert_eq!(row.get::<_, i64>(0), 0, "{table} holds the credential");
    }
    // And a debug print of the carrier redacts it.
    assert_eq!(
        format!("{:?}", LeakedSecret::new("ghp_supersecretvalue")),
        "LeakedSecret(redacted)"
    );
}

#[test]
fn verification_is_off_unless_an_operator_turns_it_on() {
    let ctx = Ctx::new();
    let mut hq = open(&ctx);
    hq.enroll(hq::domain::TargetKind::Github, "acme/web", "main")
        .unwrap();
    hq.scan("acme/web", None).unwrap();
    hq.add_fake_obs("acme/web", "head", leaked("aws-key", "a.js", "live-one"));

    // The default: HQ asks nobody.
    assert!(!NoVerification.enabled());
    hq.scan("acme/web", Some("head")).unwrap();
    hq.save().unwrap();
    assert!(hq_ok(&ctx, &["findings"]).contains("validity=unverified"));
}

// --- the Gate -----------------------------------------------------------------

fn gate_with(ctx: &Ctx, value: &str, verdict: Validity, baseline: bool) -> (String, Hq) {
    let mut hq = open(ctx);
    hq.enroll(hq::domain::TargetKind::Github, "acme/web", "main")
        .unwrap();
    if baseline {
        // The secret is already on `main`, so it lands on the Baseline.
        hq.add_fake_obs("acme/web", "main", leaked("aws-key", "a.js", value));
    }
    hq.scan("acme/web", None).unwrap();
    hq.add_fake_obs("acme/web", "head", leaked("aws-key", "a.js", value));

    let (verifier, _) = scripted(vec![(
        Box::leak(value.to_string().into_boxed_str()),
        verdict,
    )]);
    let mut hq = hq.with_verifier(verifier);
    let out = hq.handle_pr("acme/web", 42, "head", "main").unwrap();
    hq.save().unwrap();
    (out, hq)
}

#[test]
fn a_live_secret_fails_the_gate_even_on_the_baseline() {
    let ctx = Ctx::new();
    let (out, hq) = gate_with(&ctx, "live-one", Validity::Active, true);

    assert!(
        out.contains("gate=failure"),
        "a key somebody can use right now is not debt: {out}"
    );
    let dump: serde_json::Value = serde_json::from_str(&hq.github_dump()).unwrap();
    let annotation = &dump["checks"][0]["annotations"][0];
    assert_eq!(annotation["level"], "failure");
    assert!(
        annotation["title"]
            .as_str()
            .unwrap()
            .contains("credential=active"),
        "{annotation}"
    );
}

#[test]
fn a_dead_secret_does_not_fail_the_gate_on_its_own() {
    let ctx = Ctx::new();
    let (out, hq) = gate_with(&ctx, "dead-one", Validity::Inactive, false);

    assert!(out.contains("gate=success"), "{out}");
    // Still reported, just not blocking.
    let dump: serde_json::Value = serde_json::from_str(&hq.github_dump()).unwrap();
    assert_eq!(dump["checks"][0]["annotations"][0]["level"], "warning");
}

#[test]
fn an_unverified_secret_gates_exactly_as_it_did_before() {
    let ctx = Ctx::new();
    let (new_secret, _) = gate_with(&ctx, "unknown-shape", Validity::Unverified, false);
    assert!(new_secret.contains("gate=failure"), "{new_secret}");

    let ctx = Ctx::new();
    let (baseline_secret, _) = gate_with(&ctx, "unknown-shape", Validity::Unverified, true);
    assert!(
        baseline_secret.contains("gate=success"),
        "{baseline_secret}"
    );
}

// --- ranking ------------------------------------------------------------------

#[test]
fn a_live_secret_sorts_first_and_a_dead_one_last() {
    let ctx = Ctx::new();
    let mut hq = open(&ctx);
    hq.enroll(hq::domain::TargetKind::Github, "acme/web", "main")
        .unwrap();
    hq.scan("acme/web", None).unwrap();
    hq.add_fake_obs("acme/web", "head", leaked("live", "a.js", "live-one"));
    hq.add_fake_obs("acme/web", "head", leaked("dead", "b.js", "dead-one"));
    hq.add_fake_obs(
        "acme/web",
        "head",
        Observation {
            severity: Severity::Critical,
            ..leaked("cve", "c.js", "")
        },
    );
    let (verifier, _) = scripted(vec![
        ("live-one", Validity::Active),
        ("dead-one", Validity::Inactive),
    ]);
    let mut hq = hq.with_verifier(verifier);
    hq.scan("acme/web", Some("head")).unwrap();
    hq.save().unwrap();

    let order: Vec<String> = hq_ok(&ctx, &["findings"])
        .lines()
        .map(|l| l.split('|').nth(1).unwrap_or("").to_string())
        .collect();
    assert_eq!(order, vec!["live", "cve", "dead"], "live first, dead last");

    let active = hq_ok(&ctx, &["findings", "--validity", "active"]);
    assert_eq!(active.lines().count(), 1);
    assert!(active.contains("live"), "{active}");
}

#[test]
fn brief_hands_an_agent_the_live_credential_first() {
    let ctx = Ctx::new();
    let mut hq = open(&ctx);
    hq.enroll(hq::domain::TargetKind::Github, "acme/web", "main")
        .unwrap();
    hq.scan("acme/web", None).unwrap();
    hq.add_fake_obs("acme/web", "head", leaked("dead-rule", "a.js", "dead-one"));
    hq.add_fake_obs("acme/web", "head", leaked("live-rule", "z.js", "live-one"));
    let (verifier, _) = scripted(vec![
        ("live-one", Validity::Active),
        ("dead-one", Validity::Inactive),
    ]);
    let mut hq = hq.with_verifier(verifier);
    hq.scan("acme/web", Some("head")).unwrap();
    hq.save().unwrap();

    let brief = hq_ok(&ctx, &["brief"]);
    assert!(brief.contains("live-rule"), "{brief}");
    assert!(!brief.contains("dead-rule"), "{brief}");
}

// --- the providers ------------------------------------------------------------

#[test]
fn credentials_are_routed_to_the_provider_their_shape_names() {
    let verifier = ProviderVerifier::new();
    for (value, provider) in [
        ("ghp_aaaaaaaaaaaaaaaaaaaa", "github"),
        ("github_pat_11ABCDE", "github"),
        ("npm_aaaaaaaaaaaaaaaaaaaa", "npm"),
        ("xoxb-1-2-abcdef", "slack"),
        ("sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaa", "openai"),
    ] {
        assert_eq!(
            verifier.provider_for(value).map(|p| p.name),
            Some(provider),
            "{value}"
        );
    }
    // A credential HQ has no provider for is not guessed at.
    assert!(verifier.provider_for("hunter2").is_none());
    assert_eq!(verifier.check("some-rule", "hunter2"), Validity::Unverified);
}

/// Stands in for the providers' identity endpoints. Answers 200 for one token,
/// 401 for anything else, and records the requests so a test can prove HQ only
/// ever reads.
struct Providers {
    server: Arc<tiny_http::Server>,
    seen: Arc<Mutex<Vec<(String, String, String)>>>,
    calls: Arc<AtomicUsize>,
}

impl Providers {
    fn start(good: &'static str) -> (Self, String) {
        let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").expect("bind"));
        let base = format!("http://{}", server.server_addr().to_ip().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let this = Providers {
            server: server.clone(),
            seen: seen.clone(),
            calls: calls.clone(),
        };
        std::thread::spawn(move || {
            for request in server.incoming_requests() {
                calls.fetch_add(1, Ordering::Relaxed);
                let auth = request
                    .headers()
                    .iter()
                    .find(|h| h.field.equiv("Authorization"))
                    .map(|h| h.value.as_str().to_string())
                    .unwrap_or_default();
                seen.lock().unwrap().push((
                    request.method().as_str().to_string(),
                    request.url().to_string(),
                    auth.clone(),
                ));
                let live = auth == format!("Bearer {good}");
                let (code, body) = match (request.url(), live) {
                    // Slack answers 200 either way and says so in the body.
                    (u, live) if u.starts_with("/slack") => (200, format!("{{\"ok\": {live}}}")),
                    (_, true) => (200, "{\"login\": \"someone\"}".to_string()),
                    (_, false) => (401, "{\"message\": \"Bad credentials\"}".to_string()),
                };
                let response = tiny_http::Response::from_string(body).with_status_code(code);
                let _ = request.respond(response);
            }
        });
        (this, base)
    }

    fn endpoints(base: &str) -> ProviderEndpoints {
        ProviderEndpoints {
            github: format!("{base}/github/user"),
            npm: format!("{base}/npm/whoami"),
            slack: format!("{base}/slack/auth.test"),
            openai: format!("{base}/openai/models"),
        }
    }
}

impl Drop for Providers {
    fn drop(&mut self) {
        self.server.unblock();
    }
}

#[test]
fn a_live_credential_answers_active_and_a_revoked_one_answers_inactive() {
    let (stub, base) = Providers::start("ghp_livetoken0000000000");
    let verifier = ProviderVerifier::with_endpoints(Providers::endpoints(&base));

    assert_eq!(
        verifier.check("github-pat", "ghp_livetoken0000000000"),
        Validity::Active
    );
    assert_eq!(
        verifier.check("github-pat", "ghp_revokedtoken000000"),
        Validity::Inactive
    );
    // Slack says so in the body rather than the status.
    assert_eq!(
        verifier.check("slack-token", "xoxb-revoked"),
        Validity::Inactive
    );

    // Every call was a read, and the credential went only to its own provider.
    let seen = stub.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 3);
    for (method, url, auth) in &seen {
        assert_eq!(method, "GET", "verification must not mutate the account");
        assert!(auth.starts_with("Bearer "), "{auth}");
        if url.starts_with("/github") {
            assert!(auth.contains("ghp_"), "{auth}");
        }
    }
    assert_eq!(stub.calls.load(Ordering::Relaxed), 3);
}

#[test]
fn a_provider_hq_cannot_reach_leaves_the_finding_unverified() {
    // Nothing is listening on this port.
    let endpoints = ProviderEndpoints {
        github: "http://127.0.0.1:1/user".into(),
        npm: "http://127.0.0.1:1/whoami".into(),
        slack: "http://127.0.0.1:1/auth.test".into(),
        openai: "http://127.0.0.1:1/models".into(),
    };
    let verifier = ProviderVerifier::with_endpoints(endpoints);
    assert_eq!(
        verifier.check("github-pat", "ghp_whoknows0000000000"),
        Validity::Unverified,
        "an unreachable provider is not the same as a dead key"
    );
}
