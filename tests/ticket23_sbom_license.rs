//! SBOM export, and licenses as a policy decision rather than an observation.

#[allow(dead_code)]
mod common;

use common::{hq_ok, stderr, Ctx, TEST_URL};
use hq::domain::{FindingKind, Observation, Scope, Severity, TargetKind};
use hq::Hq;

fn open(ctx: &Ctx) -> Hq {
    Hq::open(TEST_URL, &ctx.schema).expect("open hq")
}

fn workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("package-lock.json"),
        r#"{"lockfileVersion": 3, "packages": {
             "": {"name": "web"},
             "node_modules/lodash": {"version": "4.17.21"},
             "node_modules/@acme/ui": {"version": "2.0.0"},
             "node_modules/jest": {"version": "29.0.0", "dev": true}}}"#,
    )
    .unwrap();
    dir
}

fn license_obs(license: &str, package: &str) -> Observation {
    Observation {
        engine: "trivy".into(),
        problem_id: license.into(),
        location_key: format!("package-lock.json::{package}"),
        kind: FindingKind::License,
        package: Some(package.into()),
        manifest: Some("package-lock.json".into()),
        fixed_version: None,
        message: String::new(),
        line: None,
        scope: Scope::Runtime,
        severity: Severity::Unknown,
        secret: None,
        snippet: None,
    }
}

fn enrolled(ctx: &Ctx) -> Hq {
    let mut hq = open(ctx);
    hq.enroll(TargetKind::Github, "acme/web", "main").unwrap();
    hq
}

// --- the SBOM -----------------------------------------------------------------

#[test]
fn sbom_emits_cyclonedx_for_the_last_scanned_revision() {
    let ctx = Ctx::new();
    let dir = workspace();
    let mut hq = enrolled(&ctx);
    hq.add_fake_obs("acme/web", "abc123", license_obs("MIT", "lodash"));
    hq.scan_named(
        "acme/web",
        Some("abc123"),
        &["fake"],
        Some(dir.path()),
        false,
    )
    .unwrap();
    hq.save().unwrap();

    let raw = hq_ok(&ctx, &["sbom", "acme/web"]);
    let bom: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");

    assert_eq!(bom["bomFormat"], "CycloneDX");
    assert_eq!(bom["specVersion"], "1.5");
    assert_eq!(bom["version"], 1);
    assert_eq!(bom["metadata"]["component"]["name"], "acme/web");
    assert_eq!(
        bom["metadata"]["component"]["version"], "abc123",
        "the Revision that was actually scanned"
    );
    assert!(bom["metadata"]["timestamp"].is_string());

    let components = bom["components"].as_array().unwrap();
    assert_eq!(components.len(), 3, "{components:#?}");
    let lodash = components.iter().find(|c| c["name"] == "lodash").unwrap();
    assert_eq!(lodash["type"], "library");
    assert_eq!(lodash["version"], "4.17.21");
    assert_eq!(lodash["purl"], "pkg:npm/lodash@4.17.21");
    assert_eq!(lodash["scope"], "required");
    assert_eq!(lodash["licenses"][0]["license"]["id"], "MIT");

    // A build-only dependency is optional, in CycloneDX's own words.
    let jest = components.iter().find(|c| c["name"] == "jest").unwrap();
    assert_eq!(jest["scope"], "optional");
    // Nobody reported a license for it, so none is claimed.
    assert!(jest.get("licenses").is_none(), "{jest}");

    // A scoped package's purl is encoded the way the spec requires.
    let scoped = components.iter().find(|c| c["name"] == "@acme/ui").unwrap();
    assert_eq!(scoped["purl"], "pkg:npm/%40acme/ui@2.0.0");

    // Every component is uniquely addressable.
    let refs: std::collections::HashSet<&str> = components
        .iter()
        .map(|c| c["bom-ref"].as_str().unwrap())
        .collect();
    assert_eq!(refs.len(), 3);
}

#[test]
fn an_sbom_for_an_unscanned_target_says_so_rather_than_looking_clean() {
    let ctx = Ctx::new();
    enrolled(&ctx).save().unwrap();

    let out = common::hq(&ctx, &["sbom", "acme/web"]);
    assert!(!out.status.success());
    let message = stderr(&out);
    assert!(message.contains("no scanned Revision"), "{message}");
    assert!(message.contains("hq scan acme/web"), "{message}");

    assert!(common::hq(&ctx, &["sbom", "ghost/repo"])
        .status
        .success()
        .eq(&false));
}

#[test]
fn the_inventory_follows_the_target_rather_than_accumulating() {
    let ctx = Ctx::new();
    let dir = workspace();
    let mut hq = enrolled(&ctx);
    hq.scan_named("acme/web", Some("r1"), &["fake"], Some(dir.path()), false)
        .unwrap();
    hq.save().unwrap();
    assert_eq!(components(&ctx).len(), 3);

    // lodash is removed in the next Revision. It must not linger in the SBOM.
    std::fs::write(
        dir.path().join("package-lock.json"),
        r#"{"lockfileVersion": 3, "packages": {"": {"name": "web"},
             "node_modules/jest": {"version": "29.0.0", "dev": true}}}"#,
    )
    .unwrap();
    let mut hq = open(&ctx);
    hq.scan_named("acme/web", Some("r2"), &["fake"], Some(dir.path()), false)
        .unwrap();
    hq.save().unwrap();

    let components = components(&ctx);
    assert_eq!(components.len(), 1, "{components:#?}");
    assert_eq!(components[0]["name"], "jest");
}

fn components(ctx: &Ctx) -> Vec<serde_json::Value> {
    let bom: serde_json::Value = serde_json::from_str(&hq_ok(ctx, &["sbom", "acme/web"])).unwrap();
    bom["components"].as_array().unwrap().clone()
}

// --- license policy -----------------------------------------------------------

fn scanned_with_licenses(ctx: &Ctx) -> Hq {
    let dir = workspace();
    let mut hq = open(ctx);
    hq.add_fake_obs("acme/web", "main", license_obs("MIT", "lodash"));
    hq.add_fake_obs("acme/web", "main", license_obs("GPL-3.0", "@acme/ui"));
    hq.add_fake_obs("acme/web", "main", license_obs("BSL-1.1", "jest"));
    hq.scan_named("acme/web", None, &["fake"], Some(dir.path()), false)
        .unwrap();
    hq.save().unwrap();
    open(ctx)
}

#[test]
fn an_operator_declares_allow_deny_and_review_lists() {
    let ctx = Ctx::new();
    enrolled(&ctx).save().unwrap();

    assert_eq!(
        hq_ok(&ctx, &["license-policy"]),
        "no license policy: every license needs review"
    );
    let set = hq_ok(
        &ctx,
        &[
            "license-policy",
            "--allow",
            "MIT, Apache-2.0",
            "--deny",
            "GPL-3.0",
            "--review",
            "BSL-1.1",
        ],
    );
    assert_eq!(set, "allow=Apache-2.0,MIT deny=GPL-3.0 review=BSL-1.1");
    // It survives the process, because it is HQ's, not a flag.
    assert_eq!(
        hq_ok(&ctx, &["license-policy"]),
        "allow=Apache-2.0,MIT deny=GPL-3.0 review=BSL-1.1"
    );
    // A license cannot be two things at once.
    assert_eq!(
        hq_ok(&ctx, &["license-policy", "--deny", "MIT"]),
        "allow=Apache-2.0 deny=GPL-3.0,MIT review=BSL-1.1"
    );
}

#[test]
fn an_allowed_license_produces_no_finding_at_all() {
    let ctx = Ctx::new();
    enrolled(&ctx).save().unwrap();
    hq_ok(
        &ctx,
        &["license-policy", "--allow", "MIT", "--deny", "GPL-3.0"],
    );
    scanned_with_licenses(&ctx);

    let findings = hq_ok(&ctx, &["findings", "--kind", "license"]);
    assert!(
        !findings.contains("MIT"),
        "allowed is not a Finding: {findings}"
    );
    assert!(findings.contains("GPL-3.0"), "{findings}");
    assert!(findings.contains("BSL-1.1"), "unlisted still needs a human");
}

#[test]
fn a_license_finding_names_the_license_and_the_rule_it_broke() {
    let ctx = Ctx::new();
    enrolled(&ctx).save().unwrap();
    hq_ok(&ctx, &["license-policy", "--deny", "GPL-3.0"]);
    scanned_with_licenses(&ctx);

    let json: serde_json::Value =
        serde_json::from_str(&hq_ok(&ctx, &["findings", "--json", "--kind", "license"])).unwrap();
    let denied = json
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["problem_id"] == "GPL-3.0")
        .expect("the denied one");
    assert_eq!(denied["package"], "@acme/ui");
    assert_eq!(denied["message"], "GPL-3.0 is denied by the license policy");

    let review = json
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["problem_id"] == "BSL-1.1")
        .expect("the unruled one");
    assert_eq!(review["message"], "BSL-1.1 is review by the license policy");
    assert_eq!(review["agent_fixable"], false, "never an agent's call");
}

#[test]
fn a_denied_license_gates_and_a_review_license_does_not() {
    let ctx = Ctx::new();
    enrolled(&ctx).save().unwrap();
    hq_ok(&ctx, &["license-policy", "--deny", "GPL-3.0"]);
    // Baseline first, with nothing in it.
    hq_ok(&ctx, &["scan", "acme/web"]);

    // A review-only license appears on the PR head: reported, not blocking.
    let mut hq = open(&ctx);
    hq.add_fake_obs("acme/web", "head", license_obs("BSL-1.1", "jest"));
    let out = hq.handle_pr("acme/web", 42, "head", "main").unwrap();
    hq.save().unwrap();
    assert!(out.contains("gate=success"), "{out}");
    let dump: serde_json::Value = serde_json::from_str(&hq.github_dump()).unwrap();
    assert_eq!(
        dump["checks"][0]["annotations"][0]["level"], "warning",
        "still reported"
    );

    // A denied one blocks like any other new Finding.
    let mut hq = open(&ctx);
    hq.add_fake_obs("acme/web", "head2", license_obs("GPL-3.0", "@acme/ui"));
    let out = hq.handle_pr("acme/web", 43, "head2", "main").unwrap();
    hq.save().unwrap();
    assert!(out.contains("gate=failure"), "{out}");
}

#[test]
fn nothing_auto_accepts_a_license() {
    let ctx = Ctx::new();
    enrolled(&ctx).save().unwrap();
    scanned_with_licenses(&ctx);

    // With no policy at all, every license needs a human and none is accepted.
    let findings = hq_ok(&ctx, &["findings", "--kind", "license"]);
    assert_eq!(findings.lines().count(), 3, "{findings}");
    assert!(
        findings.lines().all(|l| l.contains("state=Open")),
        "{findings}"
    );

    // An agent asking for work is never handed one.
    let brief = hq_ok(&ctx, &["findings", "--json", "--kind", "license"]);
    let json: serde_json::Value = serde_json::from_str(&brief).unwrap();
    assert!(
        json.as_array()
            .unwrap()
            .iter()
            .all(|f| f["agent_fixable"] == false),
        "{brief}"
    );
}
