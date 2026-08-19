//! What a Target actually depends on.
//!
//! Engines report problems, not inventories: trivy names the packages that have
//! CVEs and says nothing about the rest. Several things HQ does — deciding
//! scope, checking names against malicious-package advisories, writing an SBOM —
//! need the whole list, and the Target's own lockfiles are where it lives.

use crate::domain::Scope;
use serde_json::Value;
use std::path::Path;

/// One resolved dependency.
#[derive(Debug, Clone, PartialEq)]
pub struct Package {
    /// The package manager's name for its own registry, spelled the way public
    /// advisory databases spell it.
    pub ecosystem: String,
    pub name: String,
    pub version: Option<String>,
    /// The manifest it was resolved in, relative to the workspace.
    pub manifest: String,
    pub scope: Scope,
}

/// One entry as the lockfile records it, before HQ decides anything about it.
#[derive(Debug, Clone, PartialEq)]
pub struct LockEntry {
    pub name: String,
    pub version: Option<String>,
    pub dev: bool,
}

/// Directories that are never a Target's own source.
const SKIP: [&str; 6] = ["node_modules", ".git", "vendor", "target", "dist", ".venv"];
/// A lockfile nested more than this deep is somebody else's problem.
const MAX_DEPTH: usize = 6;

/// Every dependency HQ can see in a checkout.
pub fn read(workspace: &Path) -> Vec<Package> {
    let mut out = Vec::new();
    for manifest in manifests(workspace, workspace, 0) {
        let path = workspace.join(&manifest);
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let entries = match name {
            "package-lock.json" => npm_lock_entries(&text),
            "package.json" => npm_package_entries(&text),
            _ => continue,
        };
        for entry in entries {
            out.push(Package {
                ecosystem: "npm".into(),
                name: entry.name,
                version: entry.version,
                manifest: manifest.clone(),
                scope: if entry.dev {
                    Scope::Development
                } else {
                    Scope::Runtime
                },
            });
        }
    }
    out
}

/// Lockfiles win: where a directory has both, `package.json` only repeats what
/// the lockfile already resolved, at ranges rather than versions.
fn manifests(root: &Path, dir: &Path, depth: usize) -> Vec<String> {
    let mut out = Vec::new();
    if depth > MAX_DEPTH {
        return out;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    let mut subdirs = Vec::new();
    let mut has_lock = false;
    let mut has_package = false;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if path.is_dir() {
            if !SKIP.contains(&name.as_str()) && !name.starts_with('.') {
                subdirs.push(path);
            }
        } else if name == "package-lock.json" {
            has_lock = true;
        } else if name == "package.json" {
            has_package = true;
        }
    }
    let relative = |file: &str| {
        dir.strip_prefix(root)
            .ok()
            .map(|p| {
                if p.as_os_str().is_empty() {
                    file.to_string()
                } else {
                    format!("{}/{file}", p.to_string_lossy())
                }
            })
            .unwrap_or_else(|| file.to_string())
    };
    if has_lock {
        out.push(relative("package-lock.json"));
    } else if has_package {
        out.push(relative("package.json"));
    }
    for sub in subdirs {
        out.extend(manifests(root, &sub, depth + 1));
    }
    out
}

/// npm's lockfile, both shapes. npm has already worked out which packages are
/// reachable only through `devDependencies`, at any depth.
pub fn npm_lock_entries(text: &str) -> Vec<LockEntry> {
    let Ok(lock): Result<Value, _> = serde_json::from_str(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    // v2/v3: a flat map keyed by install path.
    if let Some(packages) = lock.get("packages").and_then(Value::as_object) {
        for (path, entry) in packages {
            let Some(name) = package_name(path) else {
                continue;
            };
            out.push(LockEntry {
                name,
                version: entry
                    .get("version")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                dev: entry.get("dev").and_then(Value::as_bool).unwrap_or(false),
            });
        }
    }
    // v1: a tree keyed by package name.
    if let Some(deps) = lock.get("dependencies").and_then(Value::as_object) {
        walk_v1(deps, &mut out);
    }
    out
}

fn walk_v1(deps: &serde_json::Map<String, Value>, out: &mut Vec<LockEntry>) {
    for (name, entry) in deps {
        out.push(LockEntry {
            name: name.clone(),
            version: entry
                .get("version")
                .and_then(Value::as_str)
                .map(str::to_string),
            dev: entry.get("dev").and_then(Value::as_bool).unwrap_or(false),
        });
        if let Some(nested) = entry.get("dependencies").and_then(Value::as_object) {
            walk_v1(nested, out);
        }
    }
}

/// `package.json` alone: the declared dependencies, at ranges rather than
/// resolved versions, which is all a Target without a lockfile can say.
pub fn npm_package_entries(text: &str) -> Vec<LockEntry> {
    let Ok(pkg): Result<Value, _> = serde_json::from_str(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (field, dev) in [
        ("dependencies", false),
        ("optionalDependencies", false),
        ("peerDependencies", false),
        ("devDependencies", true),
    ] {
        if let Some(map) = pkg.get(field).and_then(Value::as_object) {
            for (name, range) in map {
                out.push(LockEntry {
                    name: name.clone(),
                    version: range.as_str().map(str::to_string),
                    dev,
                });
            }
        }
    }
    out
}

/// `node_modules/@scope/pkg/node_modules/dep` is a copy of `dep`. The root
/// entry, keyed by the empty string, is the Target itself.
fn package_name(path: &str) -> Option<String> {
    let (_, name) = path.rsplit_once("node_modules/")?;
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}
