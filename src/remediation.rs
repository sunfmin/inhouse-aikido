//! Turning "this package has a known fixed version" into something a Developer
//! can merge.
//!
//! HQ does not hand-write a lockfile. It checks the default Revision out, lets
//! the ecosystem's own tool resolve the pin, and pushes the result as a branch.
//! An ecosystem HQ does not know how to pin gets no Remediation at all —
//! a placeholder edit that looks like a fix is worse than none.

use crate::domain::PrFile;
use crate::workspace::Checkout;
use std::path::Path;
use std::process::Command;

/// One prepared pin: a branch on the Target, and what it changed.
#[derive(Debug, Clone)]
pub struct PreparedPin {
    pub branch: String,
    pub files: Vec<PrFile>,
}

/// How a pin becomes a branch. A port so HQ's Remediation rules can be tested
/// without git, npm, or a network.
pub trait Remediator: Send + Sync {
    /// Prepare a pin of `package` to `version` in `manifest`, on top of
    /// `base_revision`. `Ok(None)` means HQ cannot safely pin this manifest and
    /// should open nothing.
    fn prepare(
        &mut self,
        repo: &str,
        base_revision: &str,
        manifest: &str,
        package: &str,
        version: &str,
    ) -> Result<Option<PreparedPin>, String>;
}

/// The branch name for one pin. Stable, so re-running lands on the same branch.
pub fn branch_name(package: &str, version: &str) -> String {
    let slug: String = format!("{package}-{version}")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    format!("hq/pin-{slug}")
}

// --- ecosystems --------------------------------------------------------------

/// A package ecosystem HQ knows how to pin.
pub trait Ecosystem: Send + Sync {
    fn name(&self) -> &str;
    /// Does this manifest belong to this ecosystem?
    fn owns(&self, manifest: &str) -> bool;
    /// Apply the pin inside `workspace`, returning the files it changed.
    fn pin(
        &self,
        workspace: &Path,
        manifest: &str,
        package: &str,
        version: &str,
    ) -> Result<Vec<PrFile>, String>;
}

pub struct Npm;

/// Where a pin belongs in a package.json.
#[derive(Debug, PartialEq, Eq)]
pub enum NpmPin {
    /// The Target declares this package: bump the range it declares.
    Direct(&'static str),
    /// Something else pulled it in: an override, because a transitive package
    /// is not ours to declare as a dependency.
    Override,
}

impl Npm {
    /// Which section a pin goes in, without touching disk.
    pub fn placement(manifest: &serde_json::Value, package: &str) -> NpmPin {
        for section in ["dependencies", "devDependencies", "optionalDependencies"] {
            if manifest.get(section).and_then(|d| d.get(package)).is_some() {
                // The section names are literals above, so this is always one of them.
                let named: &'static str = match section {
                    "dependencies" => "dependencies",
                    "devDependencies" => "devDependencies",
                    _ => "optionalDependencies",
                };
                return NpmPin::Direct(named);
            }
        }
        NpmPin::Override
    }

    /// Apply the pin to a package.json's text, preserving key order so the diff
    /// a Developer reviews is one line.
    pub fn edit_package_json(source: &str, package: &str, version: &str) -> Result<String, String> {
        let mut doc: serde_json::Value =
            serde_json::from_str(source).map_err(|e| format!("package.json is not JSON: {e}"))?;
        if !doc.is_object() {
            return Err("package.json is not an object".into());
        }
        match Self::placement(&doc, package) {
            NpmPin::Direct(section) => {
                doc[section][package] = serde_json::Value::String(version.to_string());
            }
            NpmPin::Override => {
                if doc.get("overrides").is_none() {
                    doc["overrides"] = serde_json::json!({});
                }
                doc["overrides"][package] = serde_json::Value::String(version.to_string());
            }
        }
        let mut out = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?;
        out.push('\n');
        Ok(out)
    }
}

impl Ecosystem for Npm {
    fn name(&self) -> &str {
        "npm"
    }

    fn owns(&self, manifest: &str) -> bool {
        let file = manifest.rsplit('/').next().unwrap_or(manifest);
        matches!(
            file,
            "package-lock.json" | "npm-shrinkwrap.json" | "package.json"
        )
    }

    fn pin(
        &self,
        workspace: &Path,
        manifest: &str,
        package: &str,
        version: &str,
    ) -> Result<Vec<PrFile>, String> {
        let dir = match manifest.rsplit_once('/') {
            Some((parent, _)) => workspace.join(parent),
            None => workspace.to_path_buf(),
        };
        let package_json = dir.join("package.json");
        let source = std::fs::read_to_string(&package_json)
            .map_err(|e| format!("cannot read {}: {e}", package_json.display()))?;
        let edited = Self::edit_package_json(&source, package, version)?;
        std::fs::write(&package_json, &edited)
            .map_err(|e| format!("cannot write {}: {e}", package_json.display()))?;

        // npm owns the lockfile. HQ resolves through it rather than guessing at
        // a tree it would get wrong. Scripts stay off: this is someone else's
        // dependency graph.
        let out = Command::new("npm")
            .current_dir(&dir)
            .args([
                "install",
                "--package-lock-only",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
            ])
            .output()
            .map_err(|e| format!("cannot run npm: {e} — is npm on PATH?"))?;
        if !out.status.success() {
            return Err(format!(
                "npm could not resolve {package}@{version}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }

        let mut files = vec![PrFile {
            path: relative(manifest, "package.json"),
            content: edited,
        }];
        let lock = dir.join("package-lock.json");
        if let Ok(content) = std::fs::read_to_string(&lock) {
            files.push(PrFile {
                path: relative(manifest, "package-lock.json"),
                content,
            });
        }
        Ok(files)
    }
}

/// A sibling of `manifest`, as a repo-relative path.
fn relative(manifest: &str, file: &str) -> String {
    match manifest.rsplit_once('/') {
        Some((parent, _)) => format!("{parent}/{file}"),
        None => file.to_string(),
    }
}

pub fn ecosystems() -> Vec<Box<dyn Ecosystem>> {
    vec![Box::new(Npm)]
}

// --- the real remediator -----------------------------------------------------

/// Checks the Target out, lets the ecosystem resolve the pin, and pushes a
/// branch ready to become a pull request.
pub struct GitRemediator {
    checkout: Box<dyn Checkout>,
    ecosystems: Vec<Box<dyn Ecosystem>>,
}

impl GitRemediator {
    pub fn new(checkout: Box<dyn Checkout>) -> Self {
        Self {
            checkout,
            ecosystems: ecosystems(),
        }
    }

    /// Pin with a different set of ecosystems. Tests use this to exercise the
    /// branch-and-push path without npm and a registry.
    pub fn with_ecosystems(mut self, ecosystems: Vec<Box<dyn Ecosystem>>) -> Self {
        self.ecosystems = ecosystems;
        self
    }
}

impl Remediator for GitRemediator {
    fn prepare(
        &mut self,
        repo: &str,
        base_revision: &str,
        manifest: &str,
        package: &str,
        version: &str,
    ) -> Result<Option<PreparedPin>, String> {
        let Some(ecosystem) = self.ecosystems.iter().find(|e| e.owns(manifest)) else {
            return Ok(None);
        };
        let workspace = self.checkout.checkout(repo, base_revision)?;
        let files = ecosystem.pin(workspace.path(), manifest, package, version)?;
        let branch = branch_name(package, version);
        let message = format!("Pin {package} to {version} in {manifest}");
        self.checkout
            .publish_branch(repo, workspace.path(), &branch, &message)?;
        Ok(Some(PreparedPin { branch, files }))
    }
}

/// What HQ has before anyone wires a Remediator. It refuses loudly rather than
/// inventing a branch, so a half-wired HQ cannot open a pull request pointing at
/// a branch that does not exist.
pub struct UnconfiguredRemediator;

impl Remediator for UnconfiguredRemediator {
    fn prepare(
        &mut self,
        repo: &str,
        _base_revision: &str,
        _manifest: &str,
        package: &str,
        _version: &str,
    ) -> Result<Option<PreparedPin>, String> {
        Err(format!(
            "no Remediator is configured, so HQ cannot prepare the pin of {package} on {repo}"
        ))
    }
}

/// The Remediator HQ uses with the fake GitHub backend: no git, no npm, no
/// network. It stands in for a prepared branch so the Remediation *rules* —
/// one pin is one PR, secrets get none, Findings are linked — can be tested on
/// their own. It never produces a mergeable edit and is never used against a
/// real Target.
pub struct SyntheticRemediator;

impl Remediator for SyntheticRemediator {
    fn prepare(
        &mut self,
        _repo: &str,
        _base_revision: &str,
        manifest: &str,
        package: &str,
        version: &str,
    ) -> Result<Option<PreparedPin>, String> {
        Ok(Some(PreparedPin {
            branch: branch_name(package, version),
            files: vec![PrFile {
                path: manifest.to_string(),
                content: format!("# pin {package} = {version}\n"),
            }],
        }))
    }
}
