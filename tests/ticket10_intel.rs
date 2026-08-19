mod common;
use common::hq_ok;

#[test]
fn intel_rescan_new_cve_no_baseline_pr_storm() {
    let ctx = common::Ctx::new();
    hq_ok(
        &ctx,
        &["enroll", "github", "acme/api", "--revision", "main"],
    );
    hq_ok(
        &ctx,
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
    hq_ok(&ctx, &["scan", "acme/api"]);

    hq_ok(
        &ctx,
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

    // The rescan queues one Scan per Target; a worker runs them.
    let rescan = hq_ok(&ctx, &["intel-rescan"]);
    assert!(rescan.contains("queued acme/api"), "{rescan}");
    let worked = hq_ok(&ctx, &["work", "--drain", "--workers", "1"]);
    assert_eq!(worked, "ran 1 scans");
    let findings = hq_ok(&ctx, &["findings"]);
    assert!(findings.contains("CVE-NEW"));
    assert!(findings.contains("state=Open"));

    // baseline debt does not each get a remediation; only the new lodash pin
    let dump = hq_ok(&ctx, &["github-dump"]);
    assert!(dump.contains("pin lodash"), "{dump}");
    assert!(!dump.contains("pin leftpad"), "{dump}");
}

#[test]
fn intel_rescan_skips_unenrolled() {
    let ctx = common::Ctx::new();
    hq_ok(
        &ctx,
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
    let out = hq_ok(&ctx, &["intel-rescan"]);
    assert_eq!(out, "no targets");
}
