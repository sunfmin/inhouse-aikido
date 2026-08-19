//! Malicious dependencies: a package that is the attack, not a package with a
//! bug in it.

#[allow(dead_code)]
mod common;

use common::{hq_ok, Ctx, TEST_URL};
use hq::inventory::Package;
use hq::malicious::{Advisory, AdvisorySource, NoAdvisories, OsvAdvisories};
use hq::Hq;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

fn open(ctx: &Ctx) -> Hq {
    Hq::open(TEST_URL, &ctx.schema).expect("open hq")
}

/// A checkout with a lockfile naming exactly these packages.
fn workspace(packages: &[(&str, &str, bool)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let entries: Vec<String> = packages
        .iter()
        .map(|(name, version, dev)| {
            format!(r#""node_modules/{name}": {{"version": "{version}", "dev": {dev}}}"#)
        })
        .collect();
    std::fs::write(
        dir.path().join("package-lock.json"),
        format!(
            r#"{{"lockfileVersion": 3, "packages": {{"": {{"name": "web"}}, {}}}}}"#,
            entries.join(", ")
        ),
    )
    .unwrap();
    dir
}

/// An advisory source with a fixed opinion, that counts what it was asked.
struct Advisories {
    malware: Vec<&'static str>,
    asked: Arc<Mutex<Vec<Vec<String>>>>,
    calls: Arc<AtomicUsize>,
    fail: bool,
}

impl AdvisorySource for Advisories {
    fn name(&self) -> &str {
        "scripted"
    }

    fn malicious(&self, packages: &[Package]) -> Result<HashMap<String, Advisory>, String> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.asked
            .lock()
            .unwrap()
            .push(packages.iter().map(|p| p.name.clone()).collect());
        if self.fail {
            return Err("OSV is unreachable".into());
        }
        Ok(packages
            .iter()
            .filter(|p| self.malware.contains(&p.name.as_str()))
            .map(|p| {
                (
                    p.name.clone(),
                    Advisory {
                        id: format!("MAL-2024-{}", p.name.len()),
                        summary: "exfiltrates environment variables on install".into(),
                    },
                )
            })
            .collect())
    }
}

struct Watch {
    asked: Arc<Mutex<Vec<Vec<String>>>>,
    calls: Arc<AtomicUsize>,
}

fn advisories(malware: Vec<&'static str>, fail: bool) -> (Box<Advisories>, Watch) {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let calls = Arc::new(AtomicUsize::new(0));
    (
        Box::new(Advisories {
            malware,
            asked: asked.clone(),
            calls: calls.clone(),
            fail,
        }),
        Watch { asked, calls },
    )
}

fn baselined(ctx: &Ctx) -> Hq {
    let mut hq = open(ctx);
    hq.enroll(hq::domain::TargetKind::Github, "acme/web", "main")
        .unwrap();
    hq.scan("acme/web", None).expect("baseline");
    hq.save().unwrap();
    hq
}

// --- advisories ---------------------------------------------------------------

#[test]
fn a_dependency_named_in_an_advisory_becomes_a_malicious_finding() {
    let ctx = Ctx::new();
    let hq = baselined(&ctx);
    let dir = workspace(&[("lodash", "4.17.21", false), ("evil-pkg", "1.0.0", false)]);

    let (source, watch) = advisories(vec!["evil-pkg"], false);
    let mut hq = hq.with_advisories(source);
    hq.scan_named("acme/web", None, &["fake"], Some(dir.path()), false)
        .unwrap();
    hq.save().unwrap();

    assert_eq!(
        watch.calls.load(Ordering::Relaxed),
        1,
        "one batched question"
    );
    let asked = watch.asked.lock().unwrap().clone();
    assert!(asked[0].contains(&"lodash".to_string()), "{asked:?}");

    let findings = hq_ok(&ctx, &["findings"]);
    // Distinguishable from an ordinary vulnerable dependency.
    assert!(findings.contains("kind=Malicious"), "{findings}");
    assert!(findings.contains("MAL-2024"), "{findings}");
    assert!(!findings.contains("lodash"), "{findings}");

    let only = hq_ok(&ctx, &["findings", "--kind", "malicious"]);
    assert_eq!(only.lines().count(), 1, "{only}");

    let json: serde_json::Value =
        serde_json::from_str(&hq_ok(&ctx, &["findings", "--json", "--kind", "malicious"])).unwrap();
    assert_eq!(json[0]["kind"], "malicious");
    assert_eq!(json[0]["package"], "evil-pkg");
    assert_eq!(json[0]["severity"], "critical");
    assert_eq!(json[0]["fixed_version"], serde_json::Value::Null);
}

#[test]
fn a_malicious_dependency_fails_the_gate_even_on_the_baseline() {
    let ctx = Ctx::new();
    let dir = workspace(&[("evil-pkg", "1.0.0", false)]);
    let mut hq = open(&ctx);
    hq.enroll(hq::domain::TargetKind::Github, "acme/web", "main")
        .unwrap();

    // It is already on `main`, so it lands on the Baseline.
    let (source, _) = advisories(vec!["evil-pkg"], false);
    let mut hq = hq.with_advisories(source);
    hq.scan_named("acme/web", None, &["fake"], Some(dir.path()), false)
        .unwrap();
    assert!(hq_ok_baseline(&ctx, &hq));

    let out = hq
        .handle_pr_named("acme/web", 42, "head", "main", &["fake"], Some(dir.path()))
        .unwrap();
    hq.save().unwrap();
    assert!(
        out.contains("gate=failure"),
        "nobody accepts malware as debt: {out}"
    );
    let dump: serde_json::Value = serde_json::from_str(&hq.github_dump()).unwrap();
    assert_eq!(dump["checks"][0]["annotations"][0]["level"], "failure");
}

fn hq_ok_baseline(_ctx: &Ctx, hq: &Hq) -> bool {
    hq.baseline_ready("acme/web")
}

#[test]
fn no_remediation_is_opened_for_a_malicious_dependency() {
    let ctx = Ctx::new();
    let hq = baselined(&ctx);
    let dir = workspace(&[("evil-pkg", "1.0.0", false)]);

    // The same package also has a CVE with a known fix. It still gets no pin:
    // every version of a malicious package is malicious.
    let mut hq = hq;
    hq.add_fake_obs(
        "acme/web",
        "main",
        hq::domain::Observation {
            engine: "trivy".into(),
            problem_id: "CVE-2024-1".into(),
            location_key: "package-lock.json::evil-pkg".into(),
            kind: hq::domain::FindingKind::Sca,
            package: Some("evil-pkg".into()),
            manifest: Some("package-lock.json".into()),
            fixed_version: Some("2.0.0".into()),
            message: "a CVE".into(),
            line: None,
            scope: hq::domain::Scope::Runtime,
            severity: hq::domain::Severity::High,
            secret: None,
            snippet: None,
        },
    );
    let (source, _) = advisories(vec!["evil-pkg"], false);
    let mut hq = hq.with_advisories(source);
    hq.scan_named("acme/web", None, &["fake"], Some(dir.path()), false)
        .unwrap();
    hq.save().unwrap();

    let dump: serde_json::Value = serde_json::from_str(&hq_ok(&ctx, &["github-dump"])).unwrap();
    assert!(
        dump["prs"].as_array().unwrap().is_empty(),
        "a bump is not a fix for malware: {dump}"
    );
}

#[test]
fn advisory_answers_are_cached_and_not_asked_again() {
    let ctx = Ctx::new();
    let hq = baselined(&ctx);
    let dir = workspace(&[("lodash", "4.17.21", false), ("evil-pkg", "1.0.0", false)]);

    let (source, watch) = advisories(vec!["evil-pkg"], false);
    let mut hq = hq.with_advisories(source);
    hq.scan_named("acme/web", None, &["fake"], Some(dir.path()), false)
        .unwrap();
    hq.save().unwrap();
    assert_eq!(watch.calls.load(Ordering::Relaxed), 1);

    // A second Scan of the same dependencies asks nobody.
    let (source, watch) = advisories(vec!["evil-pkg"], false);
    let mut hq = open(&ctx).with_advisories(source);
    hq.scan_named("acme/web", None, &["fake"], Some(dir.path()), false)
        .unwrap();
    hq.save().unwrap();
    assert_eq!(
        watch.calls.load(Ordering::Relaxed),
        0,
        "answered from cache"
    );
    assert!(
        hq_ok(&ctx, &["findings"]).contains("MAL-2024"),
        "still known"
    );
}

#[test]
fn an_unreachable_advisory_source_reports_no_malware_and_does_not_fail_the_scan() {
    let ctx = Ctx::new();
    let hq = baselined(&ctx);
    let dir = workspace(&[("evil-pkg", "1.0.0", false)]);

    let (source, _) = advisories(vec!["evil-pkg"], true);
    let mut hq = hq.with_advisories(source);
    let out = hq
        .scan_named("acme/web", None, &["fake"], Some(dir.path()), false)
        .expect("the Scan survives");
    hq.save().unwrap();

    assert!(out.contains("scanned acme/web"), "{out}");
    assert!(
        !hq_ok(&ctx, &["findings"]).contains("MAL-"),
        "nothing claimed"
    );
}

#[test]
fn advisories_are_off_unless_an_operator_turns_them_on() {
    assert!(!NoAdvisories.enabled());
    let ctx = Ctx::new();
    let hq = baselined(&ctx);
    let dir = workspace(&[("evil-pkg", "1.0.0", false)]);
    let mut hq = hq;
    hq.scan_named("acme/web", None, &["fake"], Some(dir.path()), false)
        .unwrap();
    hq.save().unwrap();
    assert!(!hq_ok(&ctx, &["findings"]).contains("MAL-"));
}

// --- typosquats ---------------------------------------------------------------

#[test]
fn a_name_one_keystroke_from_a_popular_package_is_flagged() {
    let ctx = Ctx::new();
    let hq = baselined(&ctx);
    // `lodahs` is a transposition of `lodash`; `expres` is a deletion from
    // `express`; `reactt` an insertion. `left-pad` is nothing like anything.
    let dir = workspace(&[
        ("lodahs", "1.0.0", false),
        ("expres", "1.0.0", false),
        ("left-pad", "1.3.0", false),
        ("lodash", "4.17.21", false),
    ]);
    let mut hq = hq;
    hq.scan_named("acme/web", None, &["fake"], Some(dir.path()), false)
        .unwrap();
    hq.save().unwrap();

    let findings = hq_ok(&ctx, &["findings", "--kind", "malicious"]);
    assert!(findings.contains("typosquat:lodash"), "{findings}");
    assert!(findings.contains("typosquat:express"), "{findings}");
    assert!(!findings.contains("left-pad"), "{findings}");
    // The real package is not flagged as a near-miss of itself.
    assert_eq!(findings.lines().count(), 2, "{findings}");
}

#[test]
fn a_legitimately_similar_package_can_be_dismissed_and_stays_dismissed() {
    let ctx = Ctx::new();
    let hq = baselined(&ctx);
    let dir = workspace(&[("lodahs", "1.0.0", false)]);
    let mut hq = hq;
    hq.scan_named("acme/web", None, &["fake"], Some(dir.path()), false)
        .unwrap();
    hq.save().unwrap();

    let fingerprint = "acme/web|typosquat:lodash|package-lock.json::lodahs";
    hq_ok(&ctx, &["dismiss", fingerprint]);
    assert!(hq_ok(&ctx, &["dismissed"]).contains("lodahs"));

    // Re-scanned, it stays Dismissed rather than coming back every time.
    let mut hq = open(&ctx);
    hq.scan_named("acme/web", None, &["fake"], Some(dir.path()), false)
        .unwrap();
    hq.save().unwrap();
    let findings = hq_ok(&ctx, &["findings", "--kind", "malicious"]);
    assert!(findings.contains("state=Dismissed"), "{findings}");
    // And it does not block a merge.
    let out = hq_ok(
        &ctx,
        &[
            "handle-pr",
            "--repo",
            "acme/web",
            "--number",
            "42",
            "--head",
            "head",
            "--base",
            "main",
        ],
    );
    assert!(out.contains("gate=success"), "{out}");
}

#[test]
fn edit_distance_recognises_what_a_fat_finger_actually_does() {
    use hq::malicious::{edit_distance_is_one, near_miss};
    assert!(edit_distance_is_one("lodahs", "lodash"), "transposition");
    assert!(edit_distance_is_one("lodas", "lodash"), "deletion");
    assert!(edit_distance_is_one("lodashh", "lodash"), "insertion");
    assert!(edit_distance_is_one("lodask", "lodash"), "substitution");
    assert!(!edit_distance_is_one("lodash", "lodash"), "the same name");
    assert!(!edit_distance_is_one("ldsh", "lodash"), "two edits");

    assert_eq!(near_miss("expres"), Some("express"));
    assert_eq!(near_miss("react"), None, "the real one");
    // Short names are one edit from half the registry; HQ says nothing.
    assert_eq!(near_miss("ms"), None);
}

#[test]
fn the_inventory_reads_a_target_out_of_its_lockfiles() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("api")).unwrap();
    std::fs::create_dir_all(dir.path().join("node_modules/pkg")).unwrap();
    std::fs::write(
        dir.path().join("package-lock.json"),
        r#"{"lockfileVersion": 3, "packages": {
             "": {"name": "root"},
             "node_modules/lodash": {"version": "4.17.21"},
             "node_modules/jest": {"version": "29.0.0", "dev": true}}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.path().join("api/package.json"),
        r#"{"dependencies": {"express": "^4"}}"#,
    )
    .unwrap();
    // Never read: it is somebody else's tree.
    std::fs::write(
        dir.path().join("node_modules/pkg/package.json"),
        r#"{"dependencies": {"should-not-appear": "^1"}}"#,
    )
    .unwrap();

    let packages = hq::inventory::read(dir.path());
    let names: Vec<&str> = packages.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains(&"lodash"), "{names:?}");
    assert!(names.contains(&"jest"), "{names:?}");
    assert!(names.contains(&"express"), "{names:?}");
    assert!(!names.contains(&"should-not-appear"), "{names:?}");

    let jest = packages.iter().find(|p| p.name == "jest").unwrap();
    assert_eq!(jest.scope, hq::domain::Scope::Development);
    assert_eq!(jest.version.as_deref(), Some("29.0.0"));
    let express = packages.iter().find(|p| p.name == "express").unwrap();
    assert_eq!(express.manifest, "api/package.json");
}

#[test]
#[ignore = "reaches OSV over the network"]
fn osv_answers_for_a_known_malicious_package() {
    let source = OsvAdvisories::new();
    let packages = vec![
        Package {
            ecosystem: "npm".into(),
            name: "lodash".into(),
            version: Some("4.17.21".into()),
            manifest: "package-lock.json".into(),
            scope: hq::domain::Scope::Runtime,
        },
        Package {
            ecosystem: "npm".into(),
            // Withdrawn npm malware, in OSV as a MAL- advisory.
            name: "electron-native-notify".into(),
            version: Some("1.1.6".into()),
            manifest: "package-lock.json".into(),
            scope: hq::domain::Scope::Runtime,
        },
    ];
    let out = source.malicious(&packages).expect("OSV");
    assert!(!out.contains_key("lodash"), "{out:?}");
    let hit = out.get("electron-native-notify").expect("a MAL- advisory");
    assert!(hit.id.starts_with("MAL-"), "{hit:?}");
}
