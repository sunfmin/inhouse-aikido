mod common;
use common::hq_ok;
use tempfile::tempdir;

#[test]
fn trivy_parser_two_manifests_are_two_findings() {
    let raw = r#"{
      "Results": [
        {
          "Target": "web/package-lock.json",
          "Vulnerabilities": [
            {"VulnerabilityID":"CVE-2024-1111","PkgName":"lodash","FixedVersion":"4.17.22","InstalledVersion":"4.17.20"}
          ]
        },
        {
          "Target": "worker/package-lock.json",
          "Vulnerabilities": [
            {"VulnerabilityID":"CVE-2024-1111","PkgName":"lodash","FixedVersion":"4.17.22","InstalledVersion":"4.17.20"}
          ]
        }
      ]
    }"#;
    let obs = hq::engines::trivy::observations_from_json(raw).unwrap();
    assert_eq!(obs.len(), 2);
    assert_eq!(obs[0].location_key, "web/package-lock.json::lodash");
    assert_eq!(obs[1].location_key, "worker/package-lock.json::lodash");
    assert_eq!(obs[0].fixed_version.as_deref(), Some("4.17.22"));
}

#[test]
fn trivy_same_cve_two_lockfiles_via_cli() {
    let dir = tempdir().unwrap();
    let d = dir.path();
    hq_ok(d, &["enroll", "github", "acme/mono", "--revision", "main"]);
    hq_ok(
        d,
        &[
            "fake-obs",
            "acme/mono",
            "main",
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
            "--fixed",
            "4.17.22",
        ],
    );
    hq_ok(
        d,
        &[
            "fake-obs",
            "acme/mono",
            "main",
            "--engine",
            "trivy",
            "--problem",
            "CVE-2024-1111",
            "--location",
            "worker/package-lock.json::lodash",
            "--kind",
            "sca",
            "--package",
            "lodash",
            "--manifest",
            "worker/package-lock.json",
            "--fixed",
            "4.17.22",
        ],
    );
    hq_ok(
        d,
        &[
            "fake-obs",
            "acme/mono",
            "main",
            "--engine",
            "trivy",
            "--problem",
            "GPL-3.0",
            "--location",
            "web/package-lock.json::copyleft-lib",
            "--kind",
            "license",
        ],
    );
    hq_ok(d, &["scan", "acme/mono"]);
    let findings = hq_ok(d, &["findings"]);
    assert!(findings.contains("web/package-lock.json::lodash"));
    assert!(findings.contains("worker/package-lock.json::lodash"));
    assert!(findings.contains("copyleft-lib"));
    assert!(
        findings.contains("kind=License")
            || findings.contains("kind=license")
            || findings.contains("License")
    );
}

#[test]
fn version_bump_same_cve_same_finding() {
    let dir = tempdir().unwrap();
    let d = dir.path();
    hq_ok(d, &["enroll", "github", "acme/api", "--revision", "v1"]);
    hq_ok(
        d,
        &[
            "fake-obs",
            "acme/api",
            "v1",
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
    hq_ok(d, &["scan", "acme/api", "--revision", "v1"]);
    hq_ok(
        d,
        &[
            "fake-obs",
            "acme/api",
            "v2",
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
    // change default so we scan a new default revision without treating as PR
    hq_ok(d, &["scan", "acme/api", "--revision", "v2"]);
    let findings = hq_ok(d, &["findings"]);
    let count = findings
        .lines()
        .filter(|l| l.contains("CVE-2024-1111"))
        .count();
    assert_eq!(count, 1, "{findings}");
}
