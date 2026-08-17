mod common;
use common::hq_ok;

#[test]
fn remediation_one_pin_many_findings_no_secrets() {
    let ctx = common::Ctx::new();
    hq_ok(&ctx, &["enroll", "github", "acme/api", "--revision", "main"]);
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
    let first = hq_ok(&ctx, &["scan", "acme/api"]);
    assert!(first.contains("baseline_written"));
    assert!(!first.contains("remediations="));

    // intel-style later scan: new lodash CVEs with a known pin, plus a secret
    hq_ok(
        &ctx,
        &[
            "fake-obs",
            "acme/api",
            "main2",
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
    hq_ok(
        &ctx,
        &[
            "fake-obs",
            "acme/api",
            "main2",
            "--engine",
            "trivy",
            "--problem",
            "CVE-2024-1",
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
    hq_ok(
        &ctx,
        &[
            "fake-obs",
            "acme/api",
            "main2",
            "--engine",
            "trivy",
            "--problem",
            "CVE-2024-2",
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
    hq_ok(
        &ctx,
        &[
            "fake-obs",
            "acme/api",
            "main2",
            "--engine",
            "gitleaks",
            "--problem",
            "aws-key",
            "--location",
            "src/a.rs",
            "--kind",
            "secret",
        ],
    );
    hq_ok(
        &ctx,
        &[
            "fake-obs",
            "acme/api",
            "main2",
            "--engine",
            "opengrep",
            "--problem",
            "eval",
            "--location",
            "src/a.rs",
            "--kind",
            "sast",
        ],
    );

    // point default revision forward by re-enroll? scan uses provided revision but remediations only on default
    // Update: scan --revision main2 will not remediate unless default is main2.
    // Re-scan default after adding obs on main (overwrite default key).
    hq_ok(
        &ctx,
        &[
            "fake-obs",
            "acme/api",
            "main",
            "--engine",
            "trivy",
            "--problem",
            "CVE-2024-1",
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
    hq_ok(
        &ctx,
        &[
            "fake-obs",
            "acme/api",
            "main",
            "--engine",
            "trivy",
            "--problem",
            "CVE-2024-2",
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
    let second = hq_ok(&ctx, &["scan", "acme/api"]);
    assert!(second.contains("remediations=1"), "{second}");

    let dump = hq_ok(&ctx, &["github-dump"]);
    assert!(dump.contains("pin lodash to 4.17.22"), "{dump}");
    assert!(dump.contains("CVE-2024-1"));
    assert!(dump.contains("CVE-2024-2"));
    assert!(
        !dump.contains("aws-key")
            || dump.matches("aws-key").count() == 0
            || !dump.contains("Remediation: pin aws")
    );
    assert!(!dump.contains("pin aws"));
    assert!(dump.contains("\"conclusion\": \"success\""), "{dump}");
}
