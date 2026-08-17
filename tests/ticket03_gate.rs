mod common;
use common::{hq_ok, stdout};
use tempfile::tempdir;

#[test]
fn gate_fails_only_on_new_open_findings() {
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
        ],
    );
    hq_ok(d, &["scan", "acme/api"]);

    // PR that only has baseline debt
    hq_ok(
        d,
        &[
            "fake-obs",
            "acme/api",
            "pr-debt",
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
        ],
    );
    let debt = hq_ok(
        d,
        &[
            "handle-pr",
            "--repo",
            "acme/api",
            "--number",
            "1",
            "--head",
            "pr-debt",
            "--base",
            "main",
        ],
    );
    assert!(debt.contains("gate=success"), "{debt}");

    // PR that adds a new fingerprint
    hq_ok(
        d,
        &[
            "fake-obs",
            "acme/api",
            "pr-new",
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
        ],
    );
    hq_ok(
        d,
        &[
            "fake-obs",
            "acme/api",
            "pr-new",
            "--engine",
            "gitleaks",
            "--problem",
            "aws-key",
            "--location",
            "src/app.rs",
            "--kind",
            "secret",
        ],
    );
    let fresh = hq_ok(
        d,
        &[
            "handle-pr",
            "--repo",
            "acme/api",
            "--number",
            "2",
            "--head",
            "pr-new",
            "--base",
            "main",
        ],
    );
    assert!(fresh.contains("gate=failure"), "{fresh}");
    assert!(fresh.contains("aws-key"), "{fresh}");

    let dump = hq_ok(d, &["github-dump"]);
    assert!(dump.contains("\"conclusion\": \"failure\""));
    assert!(dump.contains("aws-key"));

    // dismissed baseline fingerprint does not fail
    hq_ok(
        d,
        &["dismiss", "acme/api|CVE-OLD|package-lock.json::leftpad"],
    );
    hq_ok(
        d,
        &[
            "fake-obs",
            "acme/api",
            "pr-dismissed-base",
            "--engine",
            "trivy",
            "--problem",
            "CVE-OLD",
            "--location",
            "package-lock.json::leftpad",
            "--kind",
            "sca",
        ],
    );
    let ok = hq_ok(
        d,
        &[
            "handle-pr",
            "--repo",
            "acme/api",
            "--number",
            "3",
            "--head",
            "pr-dismissed-base",
            "--base",
            "main",
        ],
    );
    assert!(ok.contains("gate=success"), "{ok}");
}

#[test]
fn gate_fails_closed_when_engines_fail() {
    let dir = tempdir().unwrap();
    let d = dir.path();
    hq_ok(d, &["enroll", "github", "acme/api", "--revision", "main"]);
    hq_ok(d, &["scan", "acme/api"]);
    hq_ok(d, &["fake-fail", "acme/api", "broken"]);
    let out = hq_ok(
        d,
        &[
            "handle-pr",
            "--repo",
            "acme/api",
            "--number",
            "9",
            "--head",
            "broken",
            "--base",
            "main",
        ],
    );
    assert!(out.contains("gate=failure"), "{out}");
    assert!(out.contains("engines_failed"), "{out}");
    let _ = stdout;
}
