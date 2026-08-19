//! Severity and exploitability: what a human or an agent looks at first.

#[allow(dead_code)]
mod common;

use common::{hq_ok, Ctx, TEST_URL};
use hq::domain::{FindingKind, Severity};
use hq::intel::{CveIntel, IntelSource};
use hq::Hq;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

fn open(ctx: &Ctx) -> Hq {
    Hq::open(TEST_URL, &ctx.schema).expect("open hq")
}

fn enrolled(ctx: &Ctx) {
    hq_ok(ctx, &["enroll", "github", "acme/web", "--revision", "main"]);
    hq_ok(ctx, &["scan", "acme/web"]);
}

/// A vulnerable package on the PR's head Revision, at a stated severity.
fn cve_on_head(ctx: &Ctx, cve: &str, package: &str, severity: &str) {
    hq_ok(
        ctx,
        &[
            "fake-obs",
            "acme/web",
            "headsha",
            "--engine",
            "trivy",
            "--problem",
            cve,
            "--location",
            &format!("package-lock.json::{package}"),
            "--kind",
            "sca",
            "--package",
            package,
            "--manifest",
            "package-lock.json",
            "--fixed",
            "9.9.9",
            "--severity",
            severity,
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

fn fingerprints(listing: &str) -> Vec<String> {
    listing
        .lines()
        .map(|l| l.split_whitespace().next().unwrap_or("").to_string())
        .collect()
}

// --- severity from the Engines ----------------------------------------------

#[test]
fn each_engine_reports_its_own_severity() {
    let trivy = hq::engines::trivy::observations_from_json(
        r#"{"Results": [{"Target": "package-lock.json", "Vulnerabilities": [
             {"VulnerabilityID": "CVE-1", "PkgName": "lodash", "Severity": "CRITICAL"},
             {"VulnerabilityID": "CVE-2", "PkgName": "minimist", "Severity": "MEDIUM"},
             {"VulnerabilityID": "CVE-3", "PkgName": "ms"}
           ]}]}"#,
    )
    .unwrap();
    assert_eq!(trivy[0].severity, Severity::Critical);
    assert_eq!(trivy[1].severity, Severity::Medium);
    assert_eq!(trivy[2].severity, Severity::Unknown, "silence is not low");

    let opengrep = hq::engines::opengrep::observations_from_json(
        r#"{"results": [
             {"check_id": "sqli", "path": "a.py", "extra": {"severity": "ERROR"}},
             {"check_id": "style", "path": "b.py", "extra": {"severity": "INFO"}}
           ]}"#,
    )
    .unwrap();
    assert_eq!(opengrep[0].severity, Severity::High);
    assert_eq!(opengrep[1].severity, Severity::Low);

    // gitleaks reports no severity. A live credential is not an unranked
    // problem, so HQ calls it high rather than leaving it unknown.
    let gitleaks = hq::engines::gitleaks::observations_from_json(
        r#"[{"RuleID": "aws-key", "File": "config.js", "StartLine": 4}]"#,
    )
    .unwrap();
    assert_eq!(gitleaks[0].severity, Severity::High);
}

#[test]
fn a_finding_takes_the_worst_severity_any_engine_gave_it() {
    let ctx = Ctx::new();
    enrolled(&ctx);
    for engine in ["trivy", "opengrep"] {
        let severity = if engine == "trivy" { "medium" } else { "high" };
        hq_ok(
            &ctx,
            &[
                "fake-obs",
                "acme/web",
                "headsha",
                "--engine",
                engine,
                "--problem",
                "CVE-2024-0001",
                "--location",
                "package-lock.json::lodash",
                "--kind",
                "sca",
                "--severity",
                severity,
            ],
        );
    }
    hq_ok(&ctx, &["scan", "acme/web", "--revision", "headsha"]);
    assert!(hq_ok(&ctx, &["findings"]).contains("severity=high"));
}

// --- ranking ------------------------------------------------------------------

#[test]
fn findings_come_back_most_urgent_first() {
    let ctx = Ctx::new();
    enrolled(&ctx);
    cve_on_head(&ctx, "CVE-2024-0002", "low-pkg", "low");
    cve_on_head(&ctx, "CVE-2024-0003", "crit-pkg", "critical");
    cve_on_head(&ctx, "CVE-2024-0004", "kev-pkg", "medium");
    cve_on_head(&ctx, "CVE-2024-0005", "high-pkg", "high");
    // Something already being exploited outranks anything merely predicted.
    hq_ok(&ctx, &["fake-intel", "CVE-2024-0004", "--known-exploited"]);
    hq_ok(&ctx, &["fake-intel", "CVE-2024-0003", "--epss", "0.4"]);
    hq_ok(&ctx, &["scan", "acme/web", "--revision", "headsha"]);

    let order = fingerprints(&hq_ok(&ctx, &["findings"]));
    let problems: Vec<&str> = order.iter().map(|f| f.split('|').nth(1).unwrap()).collect();
    assert_eq!(
        problems,
        vec![
            "CVE-2024-0004", // known exploited
            "CVE-2024-0003", // critical
            "CVE-2024-0005", // high
            "CVE-2024-0002", // low
        ]
    );
    let listing = hq_ok(&ctx, &["findings"]);
    assert!(listing.contains("known_exploited"), "{listing}");
    assert!(listing.contains("epss=0.4000"), "{listing}");
}

#[test]
fn findings_filter_by_minimum_severity_and_by_known_exploited() {
    let ctx = Ctx::new();
    enrolled(&ctx);
    cve_on_head(&ctx, "CVE-2024-0002", "low-pkg", "low");
    cve_on_head(&ctx, "CVE-2024-0003", "crit-pkg", "critical");
    cve_on_head(&ctx, "CVE-2024-0004", "kev-pkg", "medium");
    hq_ok(&ctx, &["fake-intel", "CVE-2024-0004", "--known-exploited"]);
    hq_ok(&ctx, &["scan", "acme/web", "--revision", "headsha"]);

    let high = hq_ok(&ctx, &["findings", "--min-severity", "high"]);
    assert!(high.contains("CVE-2024-0003"), "{high}");
    assert!(!high.contains("CVE-2024-0002"), "{high}");
    assert!(!high.contains("CVE-2024-0004"), "{high}");

    let kev = hq_ok(&ctx, &["findings", "--known-exploited"]);
    assert_eq!(kev.lines().count(), 1, "{kev}");
    assert!(kev.contains("CVE-2024-0004"), "{kev}");

    let json: serde_json::Value =
        serde_json::from_str(&hq_ok(&ctx, &["findings", "--json", "--known-exploited"])).unwrap();
    assert_eq!(json[0]["known_exploited"], true);
    assert_eq!(json[0]["severity"], "medium");
}

#[test]
fn brief_picks_the_most_urgent_agent_fixable_finding() {
    let ctx = Ctx::new();
    enrolled(&ctx);
    cve_on_head(&ctx, "CVE-2024-0002", "aaa-first-alphabetically", "low");
    cve_on_head(&ctx, "CVE-2024-0009", "zzz-last-alphabetically", "critical");
    hq_ok(&ctx, &["scan", "acme/web", "--revision", "headsha"]);

    let brief = hq_ok(&ctx, &["brief"]);
    assert!(
        brief.contains("zzz-last-alphabetically"),
        "the critical one, not the first Fingerprint: {brief}"
    );

    // And exploited-in-the-wild beats a worse-looking one nobody is using.
    hq_ok(&ctx, &["fake-intel", "CVE-2024-0002", "--known-exploited"]);
    hq_ok(&ctx, &["scan", "acme/web", "--revision", "headsha"]);
    assert!(hq_ok(&ctx, &["brief"]).contains("aaa-first-alphabetically"));
}

// --- the Gate -----------------------------------------------------------------

#[test]
fn the_annotation_names_the_severity() {
    let ctx = Ctx::new();
    enrolled(&ctx);
    cve_on_head(&ctx, "CVE-2024-0003", "crit-pkg", "critical");
    hq_ok(&ctx, &["fake-intel", "CVE-2024-0003", "--known-exploited"]);
    gate(&ctx);

    let dump: serde_json::Value = serde_json::from_str(&hq_ok(&ctx, &["github-dump"])).unwrap();
    let title = dump["checks"][0]["annotations"][0]["title"]
        .as_str()
        .unwrap();
    assert!(title.contains("severity=critical"), "{title}");
    assert!(title.contains("known-exploited"), "{title}");
}

#[test]
fn the_gate_still_fails_on_a_new_low_severity_finding() {
    let ctx = Ctx::new();
    enrolled(&ctx);
    cve_on_head(&ctx, "CVE-2024-0002", "low-pkg", "low");

    // Severity ranks what to look at first. It does not decide what blocks.
    let out = gate(&ctx);
    assert!(out.contains("gate=failure"), "{out}");
}

// --- the intel source ---------------------------------------------------------

/// An intel source that remembers what it was asked, so a test can prove HQ
/// asks once per Scan rather than once per Finding.
#[derive(Default)]
struct CountingIntel {
    asked: Arc<Mutex<Vec<Vec<String>>>>,
    answer: HashMap<String, CveIntel>,
    fail: bool,
}

impl IntelSource for CountingIntel {
    fn name(&self) -> &str {
        "counting"
    }

    fn fetch(&self, cves: &[String]) -> Result<HashMap<String, CveIntel>, String> {
        self.asked.lock().unwrap().push(cves.to_vec());
        if self.fail {
            return Err("the intel service is down".into());
        }
        Ok(self.answer.clone())
    }
}

#[test]
fn one_scan_asks_the_intel_source_once_and_caches_the_answer() {
    let ctx = Ctx::new();
    enrolled(&ctx);
    cve_on_head(&ctx, "CVE-2024-0003", "crit-pkg", "critical");
    cve_on_head(&ctx, "CVE-2024-0004", "kev-pkg", "medium");

    let asked = Arc::new(Mutex::new(Vec::new()));
    let mut answer = HashMap::new();
    answer.insert(
        "CVE-2024-0004".to_string(),
        CveIntel {
            epss: Some(0.8),
            percentile: Some(0.99),
            known_exploited: true,
        },
    );
    let mut hq = open(&ctx).with_intel(Box::new(CountingIntel {
        asked: asked.clone(),
        answer,
        fail: false,
    }));
    hq.scan("acme/web", Some("headsha")).unwrap();
    hq.save().unwrap();

    let calls = asked.lock().unwrap().clone();
    assert_eq!(calls.len(), 1, "one fetch for the whole Scan: {calls:?}");
    assert_eq!(calls[0].len(), 2, "both CVEs in one request: {calls:?}");
    assert!(hq_ok(&ctx, &["findings"]).contains("known_exploited"));

    // A second Scan finds it cached and asks nobody.
    let mut hq = open(&ctx).with_intel(Box::new(CountingIntel {
        asked: asked.clone(),
        ..Default::default()
    }));
    hq.scan("acme/web", Some("headsha")).unwrap();
    hq.save().unwrap();
    assert_eq!(asked.lock().unwrap().len(), 1, "nothing refetched");
}

#[test]
fn intel_being_unavailable_does_not_fail_the_scan() {
    let ctx = Ctx::new();
    enrolled(&ctx);
    cve_on_head(&ctx, "CVE-2024-0003", "crit-pkg", "critical");

    let mut hq = open(&ctx).with_intel(Box::new(CountingIntel {
        fail: true,
        ..Default::default()
    }));
    let out = hq.scan("acme/web", Some("headsha")).expect("scan survives");
    hq.save().unwrap();

    assert!(out.contains("observations=1"), "{out}");
    // Ranked on Engine severity alone, which is where it started.
    let listing = hq_ok(&ctx, &["findings"]);
    assert!(listing.contains("severity=critical"), "{listing}");
    assert!(!listing.contains("known_exploited"), "{listing}");
}

#[test]
fn only_real_cve_ids_are_looked_up() {
    let ids = hq::intel::cve_ids(
        [
            "CVE-2021-44228",
            "CVE-2021-44228",
            "gitleaks:aws-key",
            "MIT",
            "CVE-bad",
            "javascript.express.security.audit",
        ]
        .into_iter()
        .map(str::to_string),
    );
    assert_eq!(ids, vec!["CVE-2021-44228"]);
    assert!(hq::intel::is_cve("CVE-2024-0001"));
    assert!(!hq::intel::is_cve("CVE-2024"));
    assert!(!hq::intel::is_cve("CVE-2024-0001-extra"));
}

#[test]
#[ignore = "reaches FIRST and CISA over the network"]
fn the_public_sources_answer_for_log4shell() {
    let intel = hq::intel::PublicIntel::new();
    let out = intel
        .fetch(&["CVE-2021-44228".to_string()])
        .expect("public intel");
    let log4shell = out.get("CVE-2021-44228").expect("a row for log4shell");
    assert!(log4shell.epss.unwrap_or(0.0) > 0.5, "{log4shell:?}");
    assert!(log4shell.known_exploited, "log4shell is on CISA's KEV list");
}

#[test]
fn severity_parses_what_engines_actually_write() {
    for (raw, expected) in [
        ("CRITICAL", Severity::Critical),
        ("High", Severity::High),
        ("moderate", Severity::Medium),
        ("ERROR", Severity::High),
        ("negligible", Severity::Low),
        ("", Severity::Unknown),
    ] {
        assert_eq!(Severity::parse(raw), Some(expected), "{raw}");
    }
    assert_eq!(Severity::parse("catastrophic"), None);
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::Low > Severity::Unknown);
    // Kinds are unaffected by any of this.
    assert_eq!(FindingKind::Sca, FindingKind::Sca);
}
