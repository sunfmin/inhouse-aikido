mod common;
use common::hq_ok;
use tempfile::tempdir;

#[test]
fn intel_rescan_new_cve_no_baseline_pr_storm() {
    let dir = tempdir().unwrap();
    let d = dir.path();
    hq_ok(d, &["enroll", "github", "acme/api", "--revision", "main"]);
    hq_ok(
        d,
        &[
            "fake-obs",
            "acme/api",
            "main",
            "--engine",
            "trivy",
            "--problem",
            "CVE-OLD",
            "--location",
            "package-lock.json::leftpad",
            "--kind",
            "sca",
            "--package",
            "leftpad",
            "--manifest",
            "package-lock.json",
            "--fixed",
            "2.0.0",
        ],
    );
    hq_ok(d, &["scan", "acme/api"]);

    hq_ok(
        d,
        &[
            "fake-obs",
            "acme/api",
            "main",
            "--engine",
            "trivy",
            "--problem",
            "CVE-NEW",
            "--location",
            "package-lock.json::lodash",
            "--kind",
            "sca",
            "--package",
            "lodash",
            "--manifest",
            "package-lock.json",
            "--fixed",
            "4.17.22",
        ],
    );

    let rescan = hq_ok(d, &["intel-rescan"]);
    assert!(rescan.contains("acme/api"));
    let findings = hq_ok(d, &["findings"]);
    assert!(findings.contains("CVE-NEW"));
    assert!(findings.contains("state=Open"));

    // baseline debt does not each get a remediation; only the new lodash pin
    let dump = hq_ok(d, &["github-dump"]);
    assert!(dump.contains("pin lodash"), "{dump}");
    assert!(!dump.contains("pin leftpad"), "{dump}");
}

#[test]
fn intel_rescan_skips_unenrolled() {
    let dir = tempdir().unwrap();
    let d = dir.path();
    hq_ok(
        d,
        &[
            "fake-obs",
            "ghost/repo",
            "main",
            "--engine",
            "trivy",
            "--problem",
            "CVE-X",
            "--location",
            "a::b",
            "--kind",
            "sca",
        ],
    );
    let out = hq_ok(d, &["intel-rescan"]);
    assert_eq!(out, "no targets");
}
