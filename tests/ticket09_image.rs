mod common;
use common::hq_ok;

#[test]
fn image_target_same_cve_is_second_finding() {
    let ctx = common::Ctx::new();
    hq_ok(&ctx, &["enroll", "github", "acme/api", "--revision", "abc"]);
    hq_ok(
        &ctx,
        &[
            "enroll",
            "image",
            "acme/api-image",
            "--revision",
            "sha256:1",
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
            "acme/api-image",
            "sha256:1",
            "--engine",
            "trivy",
            "--problem",
            "CVE-2024-1111",
            "--location",
            "usr/lib/lodash::lodash",
            "--kind",
            "sca",
            "--package",
            "lodash",
            "--manifest",
            "usr/lib/lodash",
        ],
    );
    let repo_scan = hq_ok(&ctx, &["scan", "acme/api"]);
    assert!(repo_scan.contains("baseline_written"));
    let img_scan = hq_ok(&ctx, &["scan", "acme/api-image"]);
    assert!(img_scan.contains("baseline_written"));

    let findings = hq_ok(&ctx, &["findings"]);
    assert!(findings.contains("acme/api|CVE-2024-1111|package-lock.json::lodash"));
    assert!(findings.contains("acme/api-image|CVE-2024-1111|usr/lib/lodash::lodash"));

    let targets = hq_ok(&ctx, &["targets"]);
    assert!(
        targets.contains("kind=Github")
            || targets.contains("kind=github")
            || targets.contains("Github")
    );
    assert!(targets.contains("Image"));
}
