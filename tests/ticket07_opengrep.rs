mod common;

#[test]
fn opengrep_parser_uses_source_path() {
    let raw = r#"{
      "results": [
        {"check_id":"javascript.lang.security.eval","path":"src/app.js","start":{"line":40},"extra":{"message":"eval"}}
      ]
    }"#;
    let obs = hq::engines::opengrep::observations_from_json(raw).unwrap();
    assert_eq!(obs.len(), 1);
    assert_eq!(obs[0].engine, "opengrep");
    assert_eq!(obs[0].problem_id, "javascript.lang.security.eval");
    assert_eq!(obs[0].location_key, "src/app.js");
    assert!(!obs[0].location_key.contains("40"));
    assert_eq!(obs[0].kind, hq::domain::FindingKind::Sast);
}

#[test]
fn opengrep_line_move_same_finding() {
    use common::hq_ok;
    use tempfile::tempdir;
    let dir = tempdir().unwrap();
    let d = dir.path();
    hq_ok(d, &["enroll", "github", "acme/api", "--revision", "a"]);
    hq_ok(
        d,
        &[
            "fake-obs",
            "acme/api",
            "a",
            "--engine",
            "opengrep",
            "--problem",
            "javascript.lang.security.eval",
            "--location",
            "src/app.js",
            "--kind",
            "sast",
        ],
    );
    hq_ok(d, &["scan", "acme/api"]);
    hq_ok(
        d,
        &[
            "fake-obs",
            "acme/api",
            "b",
            "--engine",
            "opengrep",
            "--problem",
            "javascript.lang.security.eval",
            "--location",
            "src/app.js",
            "--kind",
            "sast",
        ],
    );
    hq_ok(d, &["scan", "acme/api", "--revision", "b"]);
    let findings = hq_ok(d, &["findings"]);
    assert_eq!(findings.lines().count(), 1, "{findings}");
}

#[test]
#[ignore = "needs opengrep binary"]
fn opengrep_real_binary_scan() {
    use common::hq_ok;
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sast");
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    hq_ok(d, &["enroll", "github", "sast-demo", "--revision", "main"]);
    hq_ok(d, &["scan", "sast-demo"]);
    let out = hq_ok(
        d,
        &[
            "scan",
            "sast-demo",
            "--revision",
            "pr",
            "--workspace",
            fixture.to_str().unwrap(),
            "--use",
            "opengrep",
        ],
    );
    assert!(out.contains("observations="), "{out}");
}
