mod common;
use common::hq_ok;

#[test]
fn enroll_scan_baseline_merges_findings() {
    let ctx = common::Ctx::new();

    hq_ok(&ctx, &["enroll", "github", "acme/api", "--revision", "abc"]);
    let targets = hq_ok(&ctx, &["targets"]);
    assert!(targets.contains("acme/api"));
    assert!(targets.contains("baseline_ready=false"));

    hq_ok(
        &ctx,
        &[
            "fake-obs",
            "acme/api",
            "abc",
            "--engine",
            "trivy",
            "--problem",
            "CVE-2024-1111",
            "--location",
            "package-lock.json::lodash",
            "--kind",
            "sca",
            "--package",
            "lodash",
            "--manifest",
            "package-lock.json",
        ],
    );
    hq_ok(
        &ctx,
        &[
            "fake-obs",
            "acme/api",
            "abc",
            "--engine",
            "osv",
            "--problem",
            "CVE-2024-1111",
            "--location",
            "package-lock.json::lodash",
            "--kind",
            "sca",
            "--package",
            "lodash",
            "--manifest",
            "package-lock.json",
        ],
    );
    hq_ok(
        &ctx,
        &[
            "fake-obs",
            "acme/api",
            "abc",
            "--engine",
            "trivy",
            "--problem",
            "CVE-2024-1111",
            "--location",
            "web/package-lock.json::lodash",
            "--kind",
            "sca",
            "--package",
            "lodash",
            "--manifest",
            "web/package-lock.json",
        ],
    );

    let scan = hq_ok(&ctx, &["scan", "acme/api"]);
    assert!(scan.contains("baseline_written"), "{scan}");
    assert!(!scan.contains("remediations="), "{scan}");

    let findings = hq_ok(&ctx, &["findings"]);
    assert!(findings.contains("acme/api|CVE-2024-1111|package-lock.json::lodash"));
    assert!(findings.contains("acme/api|CVE-2024-1111|web/package-lock.json::lodash"));
    assert!(findings.contains("state=Open"));
    assert!(findings.contains("engines=trivy,osv") || findings.contains("engines=osv,trivy"));

    let fail = common::hq(&ctx, &["scan", "not-enrolled"]);
    assert!(!fail.status.success());
    assert!(common::stderr(&fail).contains("not enrolled"));
}
