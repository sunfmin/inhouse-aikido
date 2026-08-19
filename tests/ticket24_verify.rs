//! An agent fixing a Finding is not the judge of whether it fixed it.
//!
//! `hq verify` re-runs the Engines, reports what is really there, and exits
//! non-zero while the Finding is still Open — so an agent loop can branch on
//! the exit code instead of on its own optimism.

#[allow(dead_code)]
mod common;

use common::ghstub::GithubStub;
use common::{hq, hq_ok, stderr, stdout, Ctx, TEST_URL};
use hq::domain::{FindingKind, Observation, PrFile, TargetKind};
use hq::github::app::{AppAuth, AppConfig};
use hq::github::real::RealGithub;
use hq::remediation::{branch_name, PreparedPin, Remediator};
use hq::Hq;
use std::sync::{Arc, Mutex};

const KEY: &str = include_str!("fixtures/app/test-app-key.pem");

/// A workspace with one file HQ can quote from.
const SOURCE: &str = "\
const express = require('express');
const app = express();

app.get('/run', (req, res) => {
  const out = eval(req.query.cmd);
  res.send(out);
});

module.exports = app;
";

fn workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("src")).unwrap();
    std::fs::write(dir.path().join("src/app.js"), SOURCE).unwrap();
    std::fs::write(
        dir.path().join("Dockerfile"),
        "FROM node:20\nUSER root\nCOPY . /app\n",
    )
    .unwrap();
    dir
}

fn ws(dir: &tempfile::TempDir) -> String {
    dir.path().display().to_string()
}

/// Enroll acme/web and write an empty Baseline, so anything later is new.
fn enrolled(ctx: &Ctx) {
    hq_ok(ctx, &["enroll", "github", "acme/web", "--revision", "main"]);
    hq_ok(ctx, &["scan", "acme/web", "--use", "fake"]);
}

fn seed_sast(ctx: &Ctx) {
    hq_ok(
        ctx,
        &[
            "fake-obs",
            "acme/web",
            "main",
            "--engine",
            "fake",
            "--problem",
            "javascript.lang.security.eval",
            "--location",
            "src/app.js",
            "--kind",
            "sast",
            "--line",
            "5",
            "--severity",
            "high",
            "--message",
            "eval() on user input is remote code execution",
        ],
    );
}

const FP: &str = "acme/web|javascript.lang.security.eval|src/app.js";

// --- the loop an agent runs ---------------------------------------------------

#[test]
fn verify_says_a_finding_that_is_still_there_is_still_open() {
    let ctx = Ctx::new();
    let dir = workspace();
    enrolled(&ctx);
    seed_sast(&ctx);
    hq_ok(
        &ctx,
        &[
            "scan",
            "acme/web",
            "--workspace",
            &ws(&dir),
            "--use",
            "fake",
        ],
    );

    // The agent claims it fixed it. HQ looks.
    let out = hq(
        &ctx,
        &["verify", FP, "--workspace", &ws(&dir), "--use", "fake"],
    );
    assert!(
        !out.status.success(),
        "verify must exit non-zero while the Finding is Open: {}",
        stdout(&out)
    );
    let said = stderr(&out);
    assert!(said.contains("still Open"), "got {said:?}");
    assert!(said.contains(FP), "it names the Finding: {said:?}");
    assert!(
        said.contains("main"),
        "and the Revision it looked at: {said:?}"
    );
}

#[test]
fn verify_passes_once_the_finding_is_really_gone() {
    let ctx = Ctx::new();
    let dir = workspace();
    enrolled(&ctx);
    seed_sast(&ctx);
    hq_ok(
        &ctx,
        &[
            "scan",
            "acme/web",
            "--workspace",
            &ws(&dir),
            "--use",
            "fake",
        ],
    );

    // The agent edits the tree; the Engine stops reporting it.
    hq_ok(&ctx, &["fake-clear", "acme/web", "main"]);

    let said = hq_ok(
        &ctx,
        &["verify", FP, "--workspace", &ws(&dir), "--use", "fake"],
    );
    assert!(said.contains("no longer Open"), "got {said:?}");

    // And the Finding really moved, not just the message.
    let shown = hq_ok(&ctx, &["show", FP]);
    let f: serde_json::Value = serde_json::from_str(&shown).unwrap();
    assert_eq!(f["state"], "fixed");
}

#[test]
fn verify_reports_a_finding_the_edit_opened() {
    let ctx = Ctx::new();
    let dir = workspace();
    enrolled(&ctx);
    seed_sast(&ctx);
    hq_ok(
        &ctx,
        &[
            "scan",
            "acme/web",
            "--workspace",
            &ws(&dir),
            "--use",
            "fake",
        ],
    );

    // The "fix" removes the eval and introduces a command injection.
    hq_ok(&ctx, &["fake-clear", "acme/web", "main"]);
    hq_ok(
        &ctx,
        &[
            "fake-obs",
            "acme/web",
            "main",
            "--engine",
            "fake",
            "--problem",
            "javascript.lang.security.child-process",
            "--location",
            "src/app.js",
            "--kind",
            "sast",
            "--line",
            "5",
        ],
    );

    let out = hq(
        &ctx,
        &["verify", FP, "--workspace", &ws(&dir), "--use", "fake"],
    );
    assert!(
        !out.status.success(),
        "a fix that broke something else is not a pass"
    );
    let said = stderr(&out);
    assert!(said.contains("no longer Open"), "got {said:?}");
    assert!(said.contains("opened 1 new Finding"), "got {said:?}");
    assert!(
        said.contains("javascript.lang.security.child-process"),
        "it names what it opened: {said:?}"
    );
}

#[test]
fn what_a_failing_verify_learned_is_still_recorded() {
    let ctx = Ctx::new();
    let dir = workspace();
    enrolled(&ctx);
    seed_sast(&ctx);
    hq_ok(
        &ctx,
        &[
            "scan",
            "acme/web",
            "--workspace",
            &ws(&dir),
            "--use",
            "fake",
        ],
    );

    // The eval stays, and the edit adds a second problem.
    hq_ok(
        &ctx,
        &[
            "fake-obs",
            "acme/web",
            "main",
            "--engine",
            "fake",
            "--problem",
            "javascript.lang.security.child-process",
            "--location",
            "src/app.js",
            "--kind",
            "sast",
            "--line",
            "5",
        ],
    );
    let out = hq(
        &ctx,
        &["verify", FP, "--workspace", &ws(&dir), "--use", "fake"],
    );
    assert!(!out.status.success());

    // Exiting non-zero must not throw away the Scan HQ just paid for.
    let shown = hq_ok(
        &ctx,
        &[
            "show",
            "acme/web|javascript.lang.security.child-process|src/app.js",
        ],
    );
    let f: serde_json::Value = serde_json::from_str(&shown).unwrap();
    assert_eq!(f["state"], "open");
}

#[test]
fn verify_of_an_engine_that_failed_changes_nothing() {
    let ctx = Ctx::new();
    let dir = workspace();
    enrolled(&ctx);
    seed_sast(&ctx);
    hq_ok(
        &ctx,
        &[
            "scan",
            "acme/web",
            "--workspace",
            &ws(&dir),
            "--use",
            "fake",
        ],
    );

    hq_ok(&ctx, &["fake-clear", "acme/web", "main"]);
    hq_ok(&ctx, &["fake-fail", "acme/web", "main"]);

    let out = hq(
        &ctx,
        &["verify", FP, "--workspace", &ws(&dir), "--use", "fake"],
    );
    assert!(!out.status.success(), "a failed Engine is not a pass");
    assert!(stderr(&out).contains("engines failed"), "{}", stderr(&out));

    // An Engine that could not run must not be read as "the problem is gone".
    let shown = hq_ok(&ctx, &["show", FP]);
    let f: serde_json::Value = serde_json::from_str(&shown).unwrap();
    assert_eq!(f["state"], "open");
}

#[test]
fn verify_of_an_unknown_fingerprint_is_an_error() {
    let ctx = Ctx::new();
    enrolled(&ctx);
    let out = hq(&ctx, &["verify", "acme/web|NOPE|nowhere", "--use", "fake"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("unknown finding"), "{}", stderr(&out));
}

// --- what the Brief hands the agent ------------------------------------------

#[test]
fn a_sast_brief_carries_the_rule_the_code_and_the_non_goals() {
    let ctx = Ctx::new();
    let dir = workspace();
    enrolled(&ctx);
    seed_sast(&ctx);
    hq_ok(
        &ctx,
        &[
            "scan",
            "acme/web",
            "--workspace",
            &ws(&dir),
            "--use",
            "fake",
        ],
    );

    let brief = hq_ok(&ctx, &["brief", FP]);
    // The rule, and what the Engine said about it.
    assert!(brief.contains("javascript.lang.security.eval"), "{brief}");
    assert!(brief.contains("remote code execution"), "{brief}");
    // The offending code, in context, with the line marked.
    assert!(
        brief.contains("eval(req.query.cmd)"),
        "the brief shows the code: {brief}"
    );
    assert!(
        brief.contains("const app = express();"),
        "with lines either side: {brief}"
    );
    assert!(
        brief.contains(">    5 |   const out = eval(req.query.cmd);"),
        "and marks the offending line: {brief}"
    );
    // Fix guidance and explicit non-goals.
    assert!(brief.contains("Acceptance criteria"), "{brief}");
    assert!(brief.contains("Out of scope"), "{brief}");
    assert!(
        brief.contains("nosem") || brief.contains("ignore comment"),
        "suppressing the rule is named as a non-goal: {brief}"
    );
    // And how to prove it.
    assert!(brief.contains("hq verify"), "{brief}");
}

#[test]
fn an_iac_brief_carries_the_offending_line_too() {
    let ctx = Ctx::new();
    let dir = workspace();
    enrolled(&ctx);
    hq_ok(
        &ctx,
        &[
            "fake-obs",
            "acme/web",
            "main",
            "--engine",
            "fake",
            "--problem",
            "DS002",
            "--location",
            "Dockerfile",
            "--kind",
            "iac",
            "--line",
            "2",
            "--message",
            "Image runs as root",
        ],
    );
    hq_ok(
        &ctx,
        &[
            "scan",
            "acme/web",
            "--workspace",
            &ws(&dir),
            "--use",
            "fake",
        ],
    );

    let brief = hq_ok(&ctx, &["brief", "acme/web|DS002|Dockerfile"]);
    assert!(brief.contains("DS002"), "{brief}");
    assert!(brief.contains(">    2 | USER root"), "{brief}");
    assert!(brief.contains("Out of scope"), "{brief}");
}

#[test]
fn sast_and_iac_findings_are_agent_fixable() {
    let ctx = Ctx::new();
    let dir = workspace();
    enrolled(&ctx);
    seed_sast(&ctx);
    hq_ok(
        &ctx,
        &[
            "fake-obs",
            "acme/web",
            "main",
            "--engine",
            "fake",
            "--problem",
            "DS002",
            "--location",
            "Dockerfile",
            "--kind",
            "iac",
            "--line",
            "2",
        ],
    );
    hq_ok(
        &ctx,
        &[
            "scan",
            "acme/web",
            "--workspace",
            &ws(&dir),
            "--use",
            "fake",
        ],
    );

    let raw = hq_ok(&ctx, &["findings", "--json", "--state", "open"]);
    let list: Vec<serde_json::Value> = serde_json::from_str(&raw).unwrap();
    for kind in ["sast", "iac"] {
        let f = list
            .iter()
            .find(|f| f["kind"] == kind)
            .unwrap_or_else(|| panic!("no {kind} finding in {raw}"));
        assert_eq!(f["agent_fixable"], true, "{kind} is agent work");
        let brief = hq_ok(&ctx, &["brief", f["fingerprint"].as_str().unwrap()]);
        assert!(brief.contains("Agent Brief"), "{kind}: {brief}");
    }
}

#[test]
fn a_secret_brief_never_quotes_the_line_it_was_found_on() {
    let ctx = Ctx::new();
    let dir = workspace();
    std::fs::write(
        dir.path().join("src/config.js"),
        "module.exports = { key: 'AKIAIOSFODNN7EXAMPLE' };\n",
    )
    .unwrap();
    enrolled(&ctx);
    hq_ok(
        &ctx,
        &[
            "fake-obs",
            "acme/web",
            "main",
            "--engine",
            "fake",
            "--problem",
            "aws-access-key",
            "--location",
            "src/config.js",
            "--kind",
            "secret",
            "--line",
            "1",
        ],
    );
    hq_ok(
        &ctx,
        &[
            "scan",
            "acme/web",
            "--workspace",
            &ws(&dir),
            "--use",
            "fake",
        ],
    );

    let fp = "acme/web|aws-access-key|src/config.js";
    let brief = hq_ok(&ctx, &["brief", fp]);
    assert!(
        !brief.contains("AKIAIOSFODNN7EXAMPLE"),
        "a Brief that quotes the credential leaks it again: {brief}"
    );
    let shown = hq_ok(&ctx, &["show", fp]);
    let f: serde_json::Value = serde_json::from_str(&shown).unwrap();
    assert!(
        f["snippet"].is_null(),
        "no snippet is captured for a secret"
    );
}

#[test]
fn brief_with_no_argument_still_prefers_secrets_first() {
    let ctx = Ctx::new();
    let dir = workspace();
    enrolled(&ctx);
    seed_sast(&ctx);
    hq_ok(
        &ctx,
        &[
            "fake-obs",
            "acme/web",
            "main",
            "--engine",
            "fake",
            "--problem",
            "aws-access-key",
            "--location",
            "src/config.js",
            "--kind",
            "secret",
            "--severity",
            "high",
        ],
    );
    hq_ok(
        &ctx,
        &[
            "scan",
            "acme/web",
            "--workspace",
            &ws(&dir),
            "--use",
            "fake",
        ],
    );

    let brief = hq_ok(&ctx, &["brief"]);
    assert!(
        brief.contains("aws-access-key"),
        "a live credential outranks a SAST rule: {brief}"
    );
}

// --- what HQ still refuses to do for you -------------------------------------

type Asked = Arc<Mutex<Vec<(String, String, String)>>>;

#[derive(Default)]
struct Recorder {
    asked: Asked,
}

impl Remediator for Recorder {
    fn prepare(
        &mut self,
        _repo: &str,
        _base: &str,
        manifest: &str,
        package: &str,
        version: &str,
    ) -> Result<Option<PreparedPin>, String> {
        self.asked.lock().unwrap().push((
            manifest.to_string(),
            package.to_string(),
            version.to_string(),
        ));
        Ok(Some(PreparedPin {
            branch: branch_name(package, version),
            files: vec![PrFile {
                path: manifest.to_string(),
                content: format!("{package}@{version}\n"),
            }],
        }))
    }
}

fn hq_on(stub: &GithubStub, ctx: &Ctx) -> (Hq, Asked) {
    let auth = Arc::new(Mutex::new(AppAuth::new(AppConfig::new(
        "42",
        KEY,
        stub.base.clone(),
    ))));
    let asked: Asked = Arc::new(Mutex::new(Vec::new()));
    let hq = Hq::open_with_github(TEST_URL, &ctx.schema, Box::new(RealGithub::new(auth)))
        .expect("open HQ")
        .with_remediator(Box::new(Recorder {
            asked: asked.clone(),
        }));
    (hq, asked)
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
        message: String::new(),
        line,
        scope: Default::default(),
        severity: Default::default(),
        secret: None,
        snippet: None,
    }
}

#[test]
fn hq_opens_no_remediation_that_edits_source_iac_or_secrets() {
    let ctx = Ctx::new();
    let stub = GithubStub::start();
    let (mut hq, asked) = hq_on(&stub, &ctx);
    hq.enroll(TargetKind::Github, "acme/web", "main").unwrap();
    hq.scan("acme/web", None).expect("baseline");

    hq.add_fake_obs(
        "acme/web",
        "main",
        obs("rule.eval", "src/app.js", FindingKind::Sast, Some(5)),
    );
    hq.add_fake_obs(
        "acme/web",
        "main",
        obs("DS002", "Dockerfile", FindingKind::Iac, Some(2)),
    );
    hq.add_fake_obs(
        "acme/web",
        "main",
        obs(
            "aws-access-key",
            "src/config.js",
            FindingKind::Secret,
            Some(1),
        ),
    );
    let msg = hq.scan("acme/web", None).unwrap();

    assert!(!msg.contains("remediations="), "got {msg}");
    assert!(
        asked.lock().unwrap().is_empty(),
        "HQ asked for an edit it has no business making: {:?}",
        asked.lock().unwrap()
    );
    assert!(
        stub.calls_to("POST", "/pulls").is_empty(),
        "the agent fixes source, IaC and secrets — HQ only pins dependencies"
    );
}

#[test]
fn verify_opens_no_remediation_of_its_own() {
    let ctx = Ctx::new();
    let stub = GithubStub::start();
    let (mut hq, asked) = hq_on(&stub, &ctx);
    hq.enroll(TargetKind::Github, "acme/web", "main").unwrap();
    hq.scan("acme/web", None).expect("baseline");

    let mut sca = obs(
        "CVE-2024-0001",
        "package.json::lodash",
        FindingKind::Sca,
        None,
    );
    sca.package = Some("lodash".into());
    sca.manifest = Some("package.json".into());
    sca.fixed_version = Some("4.17.21".into());
    hq.add_fake_obs("acme/web", "main", sca);
    hq.scan("acme/web", None).unwrap();
    assert_eq!(stub.calls_to("POST", "/pulls").len(), 1);
    asked.lock().unwrap().clear();

    let fp = hq::domain::Fingerprint::parse("acme/web|CVE-2024-0001|package.json::lodash").unwrap();
    let verdict = hq.verify(&fp, &["fake"], None).unwrap();
    assert!(verdict.still_open);
    assert!(
        asked.lock().unwrap().is_empty(),
        "verify reports; it does not act"
    );
    assert_eq!(
        stub.calls_to("POST", "/pulls").len(),
        1,
        "verifying must not open a second Remediation"
    );
}
