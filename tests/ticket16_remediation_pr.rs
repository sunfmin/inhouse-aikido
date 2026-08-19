//! A Remediation that is a mergeable pull request, not a placeholder.

#[allow(dead_code)]
mod common;

use common::ghstub::GithubStub;
use common::gitorigin::Origin;
use common::{Ctx, TEST_URL};
use hq::domain::{FindingKind, Observation, PrFile, TargetKind};
use hq::github::app::{AppAuth, AppConfig};
use hq::github::real::RealGithub;
use hq::remediation::{
    branch_name, Ecosystem, GitRemediator, Npm, NpmPin, PreparedPin, Remediator,
};
use hq::workspace::GitCheckout;
use hq::Hq;
use std::path::Path;
use std::sync::{Arc, Mutex};

const KEY: &str = include_str!("fixtures/app/test-app-key.pem");

// --- what goes where in a package.json ---------------------------------------

const MANIFEST: &str = r#"{
  "name": "web",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "^4.17.20",
    "express": "^4.18.0"
  },
  "devDependencies": {
    "jest": "^29.0.0"
  }
}
"#;

#[test]
fn a_declared_dependency_is_pinned_where_it_is_declared() {
    let out = Npm::edit_package_json(MANIFEST, "lodash", "4.17.21").unwrap();
    let doc: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(doc["dependencies"]["lodash"], "4.17.21");
    assert_eq!(
        doc["dependencies"]["express"], "^4.18.0",
        "nothing else moves"
    );
    assert!(doc.get("overrides").is_none(), "no override is needed");
    // The diff a Developer reviews should be one line, so key order survives.
    assert!(
        out.find("\"name\"").unwrap() < out.find("\"dependencies\"").unwrap(),
        "key order is preserved"
    );
}

#[test]
fn a_dev_dependency_is_pinned_in_dev_dependencies() {
    let out = Npm::edit_package_json(MANIFEST, "jest", "29.7.0").unwrap();
    let doc: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(doc["devDependencies"]["jest"], "29.7.0");
    assert!(doc["dependencies"].get("jest").is_none());
}

#[test]
fn a_package_the_target_never_declared_becomes_an_override() {
    // minimist is pulled in by something else. Declaring it as a dependency
    // would change what the Target depends on; an override only pins it.
    let out = Npm::edit_package_json(MANIFEST, "minimist", "1.2.8").unwrap();
    let doc: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(doc["overrides"]["minimist"], "1.2.8");
    assert!(doc["dependencies"].get("minimist").is_none());

    let parsed: serde_json::Value = serde_json::from_str(MANIFEST).unwrap();
    assert_eq!(Npm::placement(&parsed, "minimist"), NpmPin::Override);
    assert_eq!(
        Npm::placement(&parsed, "lodash"),
        NpmPin::Direct("dependencies")
    );
    assert_eq!(
        Npm::placement(&parsed, "jest"),
        NpmPin::Direct("devDependencies")
    );
}

#[test]
fn npm_claims_only_manifests_it_can_pin() {
    let npm = Npm;
    for manifest in ["package-lock.json", "web/package-lock.json", "package.json"] {
        assert!(npm.owns(manifest), "{manifest}");
    }
    for manifest in ["go.sum", "api/go.mod", "Gemfile.lock", "requirements.txt"] {
        assert!(!npm.owns(manifest), "{manifest}");
    }
}

#[test]
fn a_branch_name_is_stable_and_safe_for_git() {
    assert_eq!(branch_name("lodash", "4.17.21"), "hq/pin-lodash-4.17.21");
    let scoped = branch_name("@scope/pkg", "1.0.0");
    assert_eq!(scoped, "hq/pin--scope-pkg-1.0.0");
    assert!(!scoped.contains('@') && !scoped.contains("//"));
}

// --- the branch actually lands on the Target ---------------------------------

/// An ecosystem that just writes a file, so the branch-and-push path can be
/// tested without npm or a registry.
struct Trivial;

impl Ecosystem for Trivial {
    fn name(&self) -> &str {
        "trivial"
    }
    fn owns(&self, manifest: &str) -> bool {
        manifest.ends_with("deps.txt")
    }
    fn pin(
        &self,
        workspace: &Path,
        manifest: &str,
        package: &str,
        version: &str,
    ) -> Result<Vec<PrFile>, String> {
        let content = format!("{package}=={version}\n");
        std::fs::write(workspace.join(manifest), &content).map_err(|e| e.to_string())?;
        Ok(vec![PrFile {
            path: manifest.to_string(),
            content,
        }])
    }
}

#[test]
fn the_pin_is_committed_and_pushed_before_any_pr_exists() {
    let origin = Origin::new();
    let mut remediator = GitRemediator::new(Box::new(
        GitCheckout::default().with_clone_base(origin.clone_base()),
    ))
    .with_ecosystems(vec![Box::new(Trivial)]);

    let prepared = remediator
        .prepare("acme/web", "main", "deps.txt", "lodash", "4.17.21")
        .unwrap()
        .expect("Trivial owns deps.txt");

    assert_eq!(prepared.branch, "hq/pin-lodash-4.17.21");
    assert!(
        origin.head_of(&prepared.branch).is_some(),
        "the branch exists on the Target"
    );
    assert_eq!(
        origin.file_on(&prepared.branch, "deps.txt").unwrap(),
        "lodash==4.17.21\n",
        "and carries the edit"
    );
    assert_ne!(
        origin.head_of(&prepared.branch),
        origin.head_of("main"),
        "on a branch of its own, not on the default Revision"
    );
}

#[test]
fn preparing_the_same_pin_twice_lands_on_the_same_branch() {
    let origin = Origin::new();
    let mut remediator = GitRemediator::new(Box::new(
        GitCheckout::default().with_clone_base(origin.clone_base()),
    ))
    .with_ecosystems(vec![Box::new(Trivial)]);

    let first = remediator
        .prepare("acme/web", "main", "deps.txt", "lodash", "4.17.21")
        .unwrap()
        .unwrap();
    let second = remediator
        .prepare("acme/web", "main", "deps.txt", "lodash", "4.17.21")
        .unwrap()
        .unwrap();
    assert_eq!(first.branch, second.branch);
}

#[test]
fn an_ecosystem_hq_cannot_pin_gets_no_branch_and_no_placeholder() {
    let origin = Origin::new();
    let mut remediator = GitRemediator::new(Box::new(
        GitCheckout::default().with_clone_base(origin.clone_base()),
    ));

    let prepared = remediator
        .prepare("acme/web", "main", "api/go.sum", "grpc", "1.60.0")
        .unwrap();
    assert!(
        prepared.is_none(),
        "HQ opens nothing rather than a file that only looks like a fix"
    );
}

// --- the Remediation rules, through HQ ---------------------------------------

type Asked = Arc<Mutex<Vec<(String, String, String)>>>;

/// Records what HQ asked to be prepared, and pretends the branch is pushed.
#[derive(Default)]
struct Recorder {
    asked: Asked,
}

impl Remediator for Recorder {
    fn prepare(
        &mut self,
        _repo: &str,
        _base_revision: &str,
        manifest: &str,
        package: &str,
        version: &str,
    ) -> Result<Option<PreparedPin>, String> {
        self.asked.lock().unwrap().push((
            manifest.to_string(),
            package.to_string(),
            version.to_string(),
        ));
        Ok(Some(PreparedPin {
            branch: branch_name(package, version),
            files: vec![PrFile {
                path: manifest.to_string(),
                content: format!("{package}@{version}\n"),
            }],
        }))
    }
}

fn hq_on(stub: &GithubStub, ctx: &Ctx) -> (Hq, Asked) {
    let auth = Arc::new(Mutex::new(AppAuth::new(AppConfig::new(
        "42",
        KEY,
        stub.base.clone(),
    ))));
    let asked = Arc::new(Mutex::new(Vec::new()));
    let hq = Hq::open_with_github(TEST_URL, &ctx.schema, Box::new(RealGithub::new(auth)))
        .expect("open HQ")
        .with_remediator(Box::new(Recorder {
            asked: asked.clone(),
        }));
    (hq, asked)
}

fn sca(problem: &str, manifest: &str, package: &str, fixed: Option<&str>) -> Observation {
    Observation {
        engine: "fake".into(),
        problem_id: problem.into(),
        location_key: format!("{manifest}::{package}"),
        kind: FindingKind::Sca,
        package: Some(package.into()),
        manifest: Some(manifest.into()),
        fixed_version: fixed.map(str::to_string),
        message: format!("{problem} in {package}"),
        line: None,
        scope: Default::default(),
    }
}

fn baselined(hq: &mut Hq) {
    hq.enroll(TargetKind::Github, "acme/web", "main").unwrap();
    hq.scan("acme/web", None).expect("baseline");
}

#[test]
fn one_pin_is_one_pr_even_when_it_fixes_several_findings() {
    let ctx = Ctx::new();
    let stub = GithubStub::start();
    let (mut hq, asked) = hq_on(&stub, &ctx);
    baselined(&mut hq);

    for cve in ["CVE-2024-1", "CVE-2024-2"] {
        hq.add_fake_obs(
            "acme/web",
            "main",
            sca(cve, "package-lock.json", "lodash", Some("4.17.21")),
        );
    }
    let msg = hq.scan("acme/web", None).unwrap();
    assert!(msg.contains("remediations=1"), "got {msg}");
    assert_eq!(asked.lock().unwrap().len(), 1);

    let opened = stub.calls_to("POST", "/pulls");
    assert_eq!(opened.len(), 1);
    let body = opened[0].body["body"].as_str().unwrap();
    assert!(
        body.contains("CVE-2024-1"),
        "the PR lists what it fixes: {body}"
    );
    assert!(body.contains("CVE-2024-2"), "{body}");
    assert_eq!(opened[0].body["head"], "hq/pin-lodash-4.17.21");
    assert_eq!(opened[0].body["base"], "main");
}

#[test]
fn a_different_package_is_a_different_pr() {
    let ctx = Ctx::new();
    let stub = GithubStub::start();
    let (mut hq, _asked) = hq_on(&stub, &ctx);
    baselined(&mut hq);

    hq.add_fake_obs(
        "acme/web",
        "main",
        sca("CVE-2024-1", "package-lock.json", "lodash", Some("4.17.21")),
    );
    hq.add_fake_obs(
        "acme/web",
        "main",
        sca("CVE-2024-3", "package-lock.json", "minimist", Some("1.2.8")),
    );
    hq.scan("acme/web", None).unwrap();

    let opened = stub.calls_to("POST", "/pulls");
    assert_eq!(
        opened.len(),
        2,
        "a bad lodash bump must not block a good one"
    );
    let heads: Vec<&str> = opened
        .iter()
        .map(|c| c.body["head"].as_str().unwrap())
        .collect();
    assert!(heads.contains(&"hq/pin-lodash-4.17.21"));
    assert!(heads.contains(&"hq/pin-minimist-1.2.8"));
}

#[test]
fn re_running_does_not_open_a_second_pr_for_a_pin_that_already_has_one() {
    let ctx = Ctx::new();
    let stub = GithubStub::start();
    let (mut hq, _asked) = hq_on(&stub, &ctx);
    baselined(&mut hq);

    hq.add_fake_obs(
        "acme/web",
        "main",
        sca("CVE-2024-1", "package-lock.json", "lodash", Some("4.17.21")),
    );
    hq.scan("acme/web", None).unwrap();
    let second = hq.scan("acme/web", None).unwrap();

    assert!(!second.contains("remediations="), "got {second}");
    assert_eq!(stub.calls_to("POST", "/pulls").len(), 1);
}

#[test]
fn secrets_sast_and_iac_still_get_no_remediation() {
    let ctx = Ctx::new();
    let stub = GithubStub::start();
    let (mut hq, asked) = hq_on(&stub, &ctx);
    baselined(&mut hq);

    for kind in [FindingKind::Secret, FindingKind::Sast, FindingKind::Iac] {
        hq.add_fake_obs(
            "acme/web",
            "main",
            Observation {
                engine: "fake".into(),
                problem_id: format!("{kind:?}-1"),
                location_key: "src/app.js".into(),
                kind,
                package: Some("whatever".into()),
                manifest: Some("package-lock.json".into()),
                // Even with a version to hand, HQ does not edit source.
                fixed_version: Some("1.0.0".into()),
                message: "nope".into(),
                line: Some(3),
                scope: Default::default(),
            },
        );
    }
    let msg = hq.scan("acme/web", None).unwrap();
    assert!(!msg.contains("remediations="), "got {msg}");
    assert!(asked.lock().unwrap().is_empty());
    assert!(stub.calls_to("POST", "/pulls").is_empty());
}

#[test]
fn a_finding_with_no_known_fixed_version_gets_no_remediation() {
    let ctx = Ctx::new();
    let stub = GithubStub::start();
    let (mut hq, _asked) = hq_on(&stub, &ctx);
    baselined(&mut hq);

    hq.add_fake_obs(
        "acme/web",
        "main",
        sca("CVE-2024-9", "package-lock.json", "nofix", None),
    );
    let msg = hq.scan("acme/web", None).unwrap();
    assert!(!msg.contains("remediations="), "got {msg}");
    assert!(stub.calls_to("POST", "/pulls").is_empty());
}

#[test]
fn enrolling_a_dirty_target_is_not_a_pr_factory() {
    let ctx = Ctx::new();
    let stub = GithubStub::start();
    let (mut hq, _asked) = hq_on(&stub, &ctx);

    hq.enroll(TargetKind::Github, "acme/web", "main").unwrap();
    for i in 0..5 {
        hq.add_fake_obs(
            "acme/web",
            "main",
            sca(
                &format!("CVE-2024-{i}"),
                "package-lock.json",
                &format!("pkg{i}"),
                Some("1.0.0"),
            ),
        );
    }
    // The Baseline Scan itself.
    hq.scan("acme/web", None).unwrap();
    assert!(
        stub.calls_to("POST", "/pulls").is_empty(),
        "Baseline day opens nothing"
    );
}

#[test]
fn the_remediation_prs_own_gate_is_green_for_what_it_fixes() {
    let ctx = Ctx::new();
    let stub = GithubStub::start();
    let (mut hq, _asked) = hq_on(&stub, &ctx);
    baselined(&mut hq);

    hq.add_fake_obs(
        "acme/web",
        "main",
        sca("CVE-2024-1", "package-lock.json", "lodash", Some("4.17.21")),
    );
    hq.scan("acme/web", None).unwrap();

    let checks = stub.calls_to("POST", "/check-runs");
    let gate = checks
        .last()
        .expect("the Remediation PR gets a Gate of its own");
    assert_eq!(
        gate.body["conclusion"], "success",
        "the bot PR is mergeable: {}",
        gate.body["output"]["summary"]
    );
}

/// End to end through npm itself. Needs npm and the npm registry.
#[test]
#[ignore = "needs npm on PATH and the npm registry"]
fn npm_resolves_a_real_lockfile() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("package.json"), MANIFEST).unwrap();
    let files = Npm
        .pin(dir.path(), "package-lock.json", "lodash", "4.17.21")
        .expect("npm resolves the pin");
    assert!(files.iter().any(|f| f.path == "package.json"));
    assert!(
        files.iter().any(|f| f.path == "package-lock.json"),
        "the lockfile is part of the Remediation"
    );
}

#[test]
fn a_manifest_hq_cannot_pin_is_named_rather_than_quietly_skipped() {
    let ctx = Ctx::new();
    let stub = GithubStub::start();
    // The real Remediator, which knows only npm.
    let origin = Origin::new();
    let auth = Arc::new(Mutex::new(AppAuth::new(AppConfig::new(
        "42",
        KEY,
        stub.base.clone(),
    ))));
    let mut hq = Hq::open_with_github(TEST_URL, &ctx.schema, Box::new(RealGithub::new(auth)))
        .unwrap()
        .with_remediator(Box::new(GitRemediator::new(Box::new(
            GitCheckout::default().with_clone_base(origin.clone_base()),
        ))));
    baselined(&mut hq);

    hq.add_fake_obs(
        "acme/web",
        "main",
        sca("CVE-2024-7", "api/go.sum", "grpc", Some("1.60.0")),
    );
    let msg = hq.scan("acme/web", None).unwrap();

    assert!(
        msg.contains("unpinnable=api/go.sum"),
        "HQ says which manifest it cannot pin: {msg}"
    );
    assert!(!msg.contains("remediations="), "{msg}");
    assert!(stub.calls_to("POST", "/pulls").is_empty());
}
