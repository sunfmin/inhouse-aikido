//! HQ gets the Revision onto disk itself. Nobody hands it a clone.
//!
//! The "remote" is a git repository in a temporary directory, so these tests
//! exercise real git without reaching the network.

#[allow(dead_code)]
mod common;

use common::gitorigin::Origin;
use common::{Ctx, TEST_URL};
use hq::domain::{Observation, Revision, Target, TargetKind};
use hq::engine::{Engine, EngineError};
use hq::workspace::{Checkout, GitCheckout, Tokens};
use hq::Hq;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

type Seen = Arc<Mutex<Vec<PathBuf>>>;
type Contents = Arc<Mutex<Vec<String>>>;

/// An Engine that reads the workspace and remembers what it saw.
struct Peek {
    seen: Seen,
    contents: Contents,
    fail: bool,
}

impl Peek {
    fn new() -> (Self, Seen, Contents) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let contents = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                seen: seen.clone(),
                contents: contents.clone(),
                fail: false,
            },
            seen,
            contents,
        )
    }
}

impl Engine for Peek {
    fn name(&self) -> &str {
        "peek"
    }
    fn scan(
        &self,
        _target: &Target,
        _revision: &Revision,
        workspace: Option<&std::path::Path>,
    ) -> Result<Vec<Observation>, EngineError> {
        if let Some(dir) = workspace {
            self.seen.lock().unwrap().push(dir.to_path_buf());
            if let Ok(text) = std::fs::read_to_string(dir.join("app.js")) {
                self.contents.lock().unwrap().push(text);
            }
        }
        if self.fail {
            return Err(EngineError::Failed("peek".into()));
        }
        Ok(vec![])
    }
}

fn hq_for(ctx: &Ctx, origin: &Origin) -> Hq {
    Hq::open(TEST_URL, &ctx.schema)
        .expect("open hq")
        .with_checkout(Box::new(
            GitCheckout::default().with_clone_base(origin.clone_base()),
        ))
}

#[test]
fn a_scan_with_no_workspace_clones_the_default_revision() {
    let ctx = Ctx::new();
    let origin = Origin::new();
    let mut hq = hq_for(&ctx, &origin);
    hq.enroll(TargetKind::Github, "acme/web", "main").unwrap();

    let (peek, seen, contents) = Peek::new();
    hq.scan_with("acme/web", None, &[Box::new(peek)], None, false)
        .expect("HQ clones the Revision itself");

    assert_eq!(seen.lock().unwrap().len(), 1, "the Engine got a workspace");
    assert!(
        contents.lock().unwrap()[0].contains("AKIAIOSFODNN7EXAMPLE"),
        "and the workspace holds the Target's files"
    );
}

#[test]
fn an_exact_revision_can_be_scanned_not_only_a_branch() {
    let ctx = Ctx::new();
    let origin = Origin::new();
    let mut hq = hq_for(&ctx, &origin);
    hq.enroll(TargetKind::Github, "acme/web", "main").unwrap();

    let (peek, _seen, contents) = Peek::new();
    hq.scan_with(
        "acme/web",
        Some(&origin.sha),
        &[Box::new(peek)],
        None,
        false,
    )
    .expect("a commit SHA is a Revision like any other");
    assert_eq!(contents.lock().unwrap().len(), 1);
}

#[test]
fn the_workspace_is_gone_once_the_scan_is_over() {
    let ctx = Ctx::new();
    let origin = Origin::new();
    let mut hq = hq_for(&ctx, &origin);
    hq.enroll(TargetKind::Github, "acme/web", "main").unwrap();

    let (peek, seen, _c) = Peek::new();
    hq.scan_with("acme/web", None, &[Box::new(peek)], None, false)
        .unwrap();

    let path = seen.lock().unwrap()[0].clone();
    assert!(!path.exists(), "{} was left behind", path.display());
}

#[test]
fn the_workspace_is_gone_even_when_an_engine_fails() {
    let ctx = Ctx::new();
    let origin = Origin::new();
    let mut hq = hq_for(&ctx, &origin);
    hq.enroll(TargetKind::Github, "acme/web", "main").unwrap();

    let (mut peek, seen, _c) = Peek::new();
    peek.fail = true;
    let err = hq
        .scan_with("acme/web", None, &[Box::new(peek)], None, false)
        .unwrap_err();
    assert!(err.contains("engines failed"), "got {err}");

    let path = seen.lock().unwrap()[0].clone();
    assert!(!path.exists(), "{} was left behind", path.display());
}

#[test]
fn a_clone_that_fails_is_a_failed_scan_not_a_clean_target() {
    let ctx = Ctx::new();
    let origin = Origin::new();
    let mut hq = hq_for(&ctx, &origin);
    hq.enroll(TargetKind::Github, "acme/nope", "main").unwrap();

    let (peek, seen, _c) = Peek::new();
    let err = hq
        .scan_with("acme/nope", None, &[Box::new(peek)], None, false)
        .expect_err("a Target HQ cannot clone must not look clean");
    assert!(err.contains("acme/nope"), "got {err}");
    assert!(seen.lock().unwrap().is_empty(), "no Engine ran");
    assert!(
        hq.findings_text(Some("acme/nope"), None, None, None)
            .contains("no findings"),
        "and nothing was recorded"
    );
}

#[test]
fn an_explicit_workspace_still_bypasses_cloning() {
    let ctx = Ctx::new();
    let origin = Origin::new();
    let given = tempfile::tempdir().unwrap();
    std::fs::write(given.path().join("app.js"), "// handed to HQ\n").unwrap();

    let mut hq = Hq::open(TEST_URL, &ctx.schema)
        .unwrap()
        // A clone base that cannot work, to prove no clone is attempted.
        .with_checkout(Box::new(
            GitCheckout::default().with_clone_base("file:///definitely/not/here"),
        ));
    hq.enroll(TargetKind::Github, "acme/web", "main").unwrap();

    let (peek, seen, contents) = Peek::new();
    hq.scan_with(
        "acme/web",
        None,
        &[Box::new(peek)],
        Some(given.path()),
        false,
    )
    .expect("an explicit workspace needs no clone");

    assert_eq!(seen.lock().unwrap()[0], given.path());
    assert!(contents.lock().unwrap()[0].contains("handed to HQ"));
    let _ = origin;
}

#[test]
fn an_engine_that_reads_no_files_does_not_pay_for_a_checkout() {
    let ctx = Ctx::new();
    let mut hq = Hq::open(TEST_URL, &ctx.schema)
        .unwrap()
        .with_checkout(Box::new(
            GitCheckout::default().with_clone_base("file:///definitely/not/here"),
        ));
    hq.enroll(TargetKind::Github, "acme/web", "main").unwrap();

    hq.scan("acme/web", None)
        .expect("the fake Engine reads nothing, so nothing is cloned");
}

/// A token source that hands out something recognisable.
struct FixedToken(String);

impl Tokens for FixedToken {
    fn token_for(&mut self, _repo: &str) -> Result<Option<String>, String> {
        Ok(Some(self.0.clone()))
    }
}

#[test]
fn the_installation_token_never_reaches_disk() {
    let origin = Origin::new();
    let token = "ghs_thisisthesecrettoken";
    let mut checkout =
        GitCheckout::new(Box::new(FixedToken(token.into()))).with_clone_base(origin.clone_base());

    let workspace = checkout.checkout("acme/web", "main").expect("checkout");

    let mut carrying = Vec::new();
    let mut stack = vec![workspace.path().to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if std::fs::read(&path)
                .map(|b| String::from_utf8_lossy(&b).contains(token))
                .unwrap_or(false)
            {
                carrying.push(path);
            }
        }
    }
    assert!(
        carrying.is_empty(),
        "the token was written to {carrying:?} — it belongs in git's environment, not on disk"
    );
}

#[test]
fn a_credential_never_leaks_into_an_error_message() {
    let token = "ghs_thisisthesecrettoken";
    let mut checkout = GitCheckout::new(Box::new(FixedToken(token.into())))
        .with_clone_base("file:///definitely/not/here");
    let err = checkout.checkout("acme/web", "main").unwrap_err();
    assert!(!err.contains(token), "got {err}");
}
