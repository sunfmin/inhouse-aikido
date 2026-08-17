mod common;
use common::hq_ok;
use tempfile::tempdir;

#[test]
fn gitleaks_parser_location_is_file_not_line() {
    let raw = r#"[{"RuleID":"aws-access-key","File":"src/app.rs","StartLine":12,"Description":"AWS key"}]"#;
    let obs = hq::engines::gitleaks::observations_from_json(raw).unwrap();
    assert_eq!(obs.len(), 1);
    assert_eq!(obs[0].engine, "gitleaks");
    assert_eq!(obs[0].problem_id, "aws-access-key");
    assert_eq!(obs[0].location_key, "src/app.rs");
    assert!(!obs[0].location_key.contains("12"));
    assert_eq!(obs[0].kind, hq::domain::FindingKind::Secret);
}

#[test]
fn gitleaks_fixture_scan_gates_pr_when_binary_present() {
    if !common::binary_on_path("gitleaks") {
        eprintln!("skip: gitleaks binary not installed");
        return;
    }
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/secrets");
    let dir = tempdir().unwrap();
    let d = dir.path();
    hq_ok(
        d,
        &["enroll", "github", "secrets-demo", "--revision", "clean"],
    );
    hq_ok(d, &["scan", "secrets-demo"]);
    let out = hq_ok(
        d,
        &[
            "handle-pr",
            "--repo",
            "secrets-demo",
            "--number",
            "1",
            "--head",
            "with-secret",
            "--base",
            "clean",
            "--workspace",
            fixture.to_str().unwrap(),
            "--use",
            "gitleaks",
        ],
    );
    assert!(out.contains("gate=failure"), "{out}");
}
