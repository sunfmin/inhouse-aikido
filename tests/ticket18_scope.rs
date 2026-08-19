//! Dependency Scope: a CVE in a build-only package stops blocking merges
//! without disappearing.

#[allow(dead_code)]
mod common;

use common::{hq_ok, Ctx};
use hq::domain::{FindingKind, Observation, Scope};
use hq::scope::{npm_lock_scopes, npm_package_scopes, promote_shared_runtime};

fn enrolled(ctx: &Ctx) {
    hq_ok(ctx, &["enroll", "github", "acme/web", "--revision", "main"]);
    hq_ok(ctx, &["scan", "acme/web"]);
}

/// A vulnerable package on the PR's head Revision.
fn obs_on_head(ctx: &Ctx, package: &str, scope: &str) {
    hq_ok(
        ctx,
        &[
            "fake-obs",
            "acme/web",
            "headsha",
            "--engine",
            "trivy",
            "--problem",
            &format!("CVE-{package}"),
            "--location",
            &format!("package-lock.json::{package}"),
            "--kind",
            "sca",
            "--package",
            package,
            "--manifest",
            "package-lock.json",
            "--scope",
            scope,
        ],
    );
}

fn gate(ctx: &Ctx) -> String {
    hq_ok(
        ctx,
        &[
            "handle-pr",
            "--repo",
            "acme/web",
            "--number",
            "42",
            "--head",
            "headsha",
            "--base",
            "main",
        ],
    )
}

fn check(ctx: &Ctx) -> serde_json::Value {
    let dump: serde_json::Value = serde_json::from_str(&hq_ok(ctx, &["github-dump"])).unwrap();
    dump["checks"][0].clone()
}

#[test]
fn a_new_development_only_finding_does_not_fail_the_gate() {
    let ctx = Ctx::new();
    enrolled(&ctx);
    obs_on_head(&ctx, "eslint", "development");

    let out = gate(&ctx);
    assert!(out.contains("gate=success"), "{out}");

    // De-noised, not hidden: still Open, still listed, still on the PR.
    let findings = hq_ok(&ctx, &["findings"]);
    assert!(findings.contains("CVE-eslint"), "{findings}");
    assert!(findings.contains("state=Open"), "{findings}");
    assert!(findings.contains("scope=development"), "{findings}");

    let check = check(&ctx);
    let annotation = &check["annotations"][0];
    assert_eq!(annotation["level"], "warning");
    assert!(
        annotation["title"]
            .as_str()
            .unwrap()
            .contains("development dependency"),
        "{annotation}"
    );
}

#[test]
fn a_new_runtime_finding_still_fails_the_gate() {
    let ctx = Ctx::new();
    enrolled(&ctx);
    obs_on_head(&ctx, "lodash", "runtime");

    let out = gate(&ctx);
    assert!(out.contains("gate=failure"), "{out}");
    assert_eq!(check(&ctx)["annotations"][0]["level"], "failure");
}

#[test]
fn an_engine_that_cannot_report_scope_gates_like_runtime() {
    let ctx = Ctx::new();
    enrolled(&ctx);
    // No --scope: nobody could tell. HQ does not de-noise on a guess.
    hq_ok(
        &ctx,
        &[
            "fake-obs",
            "acme/web",
            "headsha",
            "--engine",
            "gitleaks",
            "--problem",
            "aws-key",
            "--location",
            "src/config.js",
            "--kind",
            "secret",
        ],
    );
    let out = gate(&ctx);
    assert!(out.contains("gate=failure"), "{out}");
    assert!(hq_ok(&ctx, &["findings"]).contains("scope=unknown"));
}

#[test]
fn a_development_finding_gates_when_the_operator_says_so() {
    let ctx = Ctx::new();
    enrolled(&ctx);
    obs_on_head(&ctx, "eslint", "development");
    assert!(gate(&ctx).contains("gate=success"));

    let policy = hq_ok(&ctx, &["policy", "acme/web", "--gate-dev-scope", "true"]);
    assert_eq!(policy, "acme/web gate_dev_scope=true");
    assert!(hq_ok(&ctx, &["targets"]).contains("gate_dev_scope=true"));

    let out = gate(&ctx);
    assert!(out.contains("gate=failure"), "{out}");
    assert_eq!(check(&ctx)["annotations"][0]["level"], "failure");
}

#[test]
fn findings_filter_by_scope() {
    let ctx = Ctx::new();
    enrolled(&ctx);
    obs_on_head(&ctx, "eslint", "development");
    obs_on_head(&ctx, "lodash", "runtime");
    gate(&ctx);

    let dev = hq_ok(&ctx, &["findings", "--scope", "development"]);
    assert!(dev.contains("CVE-eslint"), "{dev}");
    assert!(!dev.contains("CVE-lodash"), "{dev}");

    let runtime = hq_ok(&ctx, &["findings", "--scope", "runtime"]);
    assert!(runtime.contains("CVE-lodash"), "{runtime}");
    assert!(!runtime.contains("CVE-eslint"), "{runtime}");

    let json: serde_json::Value = serde_json::from_str(&hq_ok(
        &ctx,
        &["findings", "--json", "--scope", "development"],
    ))
    .unwrap();
    assert_eq!(json.as_array().unwrap().len(), 1);
    assert_eq!(json[0]["scope"], "development");
}

#[test]
fn a_scan_reads_the_scope_out_of_the_targets_own_lockfile() {
    let ctx = Ctx::new();
    let workspace = tempfile::tempdir().unwrap();
    std::fs::write(
        workspace.path().join("package-lock.json"),
        r#"{"lockfileVersion": 3, "packages": {
             "": {"name": "web"},
             "node_modules/lodash": {"version": "4.17.20"},
             "node_modules/eslint": {"version": "8.0.0", "dev": true}
           }}"#,
    )
    .unwrap();
    let dir = workspace.path().to_str().unwrap();

    hq_ok(
        &ctx,
        &["enroll", "github", "acme/web", "--revision", "main"],
    );
    // Neither Observation says which scope it is in; the lockfile does.
    obs_on_head(&ctx, "lodash", "unknown");
    obs_on_head(&ctx, "eslint", "unknown");
    hq_ok(
        &ctx,
        &[
            "scan",
            "acme/web",
            "--revision",
            "headsha",
            "--workspace",
            dir,
        ],
    );

    let findings = hq_ok(&ctx, &["findings"]);
    assert!(
        findings.contains("CVE-lodash|package-lock.json::lodash state=Open kind=Sca scope=runtime"),
        "{findings}"
    );
    assert!(
        findings
            .contains("CVE-eslint|package-lock.json::eslint state=Open kind=Sca scope=development"),
        "{findings}"
    );
}

#[test]
fn a_package_that_is_runtime_anywhere_in_the_target_is_runtime_everywhere() {
    let mut observations = vec![
        obs("lodash", "api/package-lock.json", Scope::Runtime),
        obs("lodash", "tools/package-lock.json", Scope::Development),
        obs("eslint", "tools/package-lock.json", Scope::Development),
    ];
    promote_shared_runtime(&mut observations);

    assert_eq!(observations[1].scope, Scope::Runtime, "shipped by the API");
    assert_eq!(observations[2].scope, Scope::Development, "tooling only");
}

fn obs(package: &str, manifest: &str, scope: Scope) -> Observation {
    Observation {
        engine: "trivy".into(),
        problem_id: format!("CVE-{package}"),
        location_key: format!("{manifest}::{package}"),
        kind: FindingKind::Sca,
        package: Some(package.into()),
        manifest: Some(manifest.into()),
        fixed_version: None,
        message: String::new(),
        line: None,
        scope,
        severity: Default::default(),
    }
}

#[test]
fn npm_lockfiles_of_both_shapes_are_read() {
    let v3 = npm_lock_scopes(
        r#"{"lockfileVersion": 3, "packages": {
             "": {"name": "web"},
             "node_modules/lodash": {"version": "4.17.20"},
             "node_modules/jest": {"version": "29.0.0", "dev": true},
             "node_modules/jest/node_modules/chalk": {"version": "4.0.0", "dev": true}
           }}"#,
    );
    assert_eq!(v3.get("lodash"), Some(&Scope::Runtime));
    assert_eq!(v3.get("jest"), Some(&Scope::Development));
    assert_eq!(v3.get("chalk"), Some(&Scope::Development));

    let v1 = npm_lock_scopes(
        r#"{"lockfileVersion": 1, "dependencies": {
             "lodash": {"version": "4.17.20"},
             "jest": {"version": "29.0.0", "dev": true,
                      "dependencies": {"chalk": {"version": "4.0.0", "dev": true}}}
           }}"#,
    );
    assert_eq!(v1.get("lodash"), Some(&Scope::Runtime));
    assert_eq!(v1.get("chalk"), Some(&Scope::Development));

    // The same package hoisted twice, dev in one place and shipped in another.
    let both = npm_lock_scopes(
        r#"{"lockfileVersion": 3, "packages": {
             "node_modules/jest/node_modules/tslib": {"version": "2.0.0", "dev": true},
             "node_modules/tslib": {"version": "2.0.0"}
           }}"#,
    );
    assert_eq!(both.get("tslib"), Some(&Scope::Runtime));

    // Nothing readable is nothing claimed.
    assert!(npm_lock_scopes("not json").is_empty());
}

#[test]
fn a_package_json_without_a_lockfile_still_names_the_dev_dependencies() {
    let scopes = npm_package_scopes(
        r#"{"dependencies": {"lodash": "^4"}, "devDependencies": {"jest": "^29"},
            "peerDependencies": {"react": "^18"}}"#,
    );
    assert_eq!(scopes.get("lodash"), Some(&Scope::Runtime));
    assert_eq!(scopes.get("jest"), Some(&Scope::Development));
    assert_eq!(scopes.get("react"), Some(&Scope::Runtime));
}
