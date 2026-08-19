#![allow(dead_code)]
//! A git repository on disk standing in for a Target on GitHub, so tests can
//! exercise real git without reaching the network.

use std::process::Command;

/// A git repository standing in for GitHub, with one commit on `main`.
pub struct Origin {
    pub dir: tempfile::TempDir,
    pub sha: String,
}

impl Origin {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = dir.path().join("acme/web");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("app.js"), "const key = 'AKIAIOSFODNN7EXAMPLE';\n").unwrap();

        let run = |args: &[&str]| {
            let out = Command::new("git")
                .current_dir(&repo)
                .env("GIT_AUTHOR_NAME", "hq")
                .env("GIT_AUTHOR_EMAIL", "hq@example.com")
                .env("GIT_COMMITTER_NAME", "hq")
                .env("GIT_COMMITTER_EMAIL", "hq@example.com")
                .args(args)
                .output()
                .expect("git");
            assert!(
                out.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        run(&["init", "--quiet", "--initial-branch", "main"]);
        // Let a fetch ask for an exact commit, the way GitHub allows.
        run(&["config", "uploadpack.allowAnySHA1InWant", "true"]);
        run(&["add", "."]);
        run(&["commit", "--quiet", "-m", "first"]);
        let sha = run(&["rev-parse", "HEAD"]);

        Self { dir, sha }
    }

    pub fn clone_base(&self) -> String {
        format!("file://{}", self.dir.path().display())
    }
}

impl Origin {
    /// What the Target's branch points at now, read straight from the origin.
    pub fn head_of(&self, branch: &str) -> Option<String> {
        let out = Command::new("git")
            .current_dir(self.dir.path().join("acme/web"))
            .args(["rev-parse", branch])
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    /// A file's contents on a branch in the origin.
    pub fn file_on(&self, branch: &str, path: &str) -> Option<String> {
        let out = Command::new("git")
            .current_dir(self.dir.path().join("acme/web"))
            .args(["show", &format!("{branch}:{path}")])
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).to_string())
    }
}
