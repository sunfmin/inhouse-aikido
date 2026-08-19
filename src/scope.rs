//! Which dependencies are shipped and which are only built with.
//!
//! An Engine reports a vulnerable package; it rarely says whether the package is
//! on the path an attacker can reach. HQ works that out from the Target's own
//! manifests, in the workspace the Scan already cloned, so a CVE in a test
//! runner stops blocking merges without anybody hand-maintaining a list.

use crate::domain::{FindingKind, Observation, Scope};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

/// Give every dependency Observation the Scope its manifest puts it in.
///
/// An Engine that already reported a Scope is left alone. A manifest HQ cannot
/// read leaves its packages Unknown, which Gates like Runtime — HQ does not
/// de-noise on a guess.
pub fn enrich(workspace: Option<&Path>, observations: &mut [Observation]) {
    if let Some(root) = workspace {
        from_manifests(root, observations);
    }
    promote_shared_runtime(observations);
}

fn from_manifests(root: &Path, observations: &mut [Observation]) {
    let mut by_manifest: HashMap<String, HashMap<String, Scope>> = HashMap::new();
    for obs in observations.iter() {
        if obs.kind != FindingKind::Sca || obs.scope != Scope::Unknown {
            continue;
        }
        let Some(manifest) = obs.manifest.clone() else {
            continue;
        };
        by_manifest
            .entry(manifest.clone())
            .or_insert_with(|| read_manifest(root, &manifest));
    }
    for obs in observations.iter_mut() {
        if obs.kind != FindingKind::Sca || obs.scope != Scope::Unknown {
            continue;
        }
        let (Some(manifest), Some(package)) = (obs.manifest.as_ref(), obs.package.as_ref()) else {
            continue;
        };
        if let Some(scope) = by_manifest.get(manifest).and_then(|m| m.get(package)) {
            obs.scope = *scope;
        }
    }
}

/// A package that is a runtime dependency anywhere in the Target is a runtime
/// dependency everywhere in it. A monorepo whose test app dev-depends on the
/// same library the API ships must not have the API's copy quietly de-noised.
pub fn promote_shared_runtime(observations: &mut [Observation]) {
    let runtime: Vec<String> = observations
        .iter()
        .filter(|o| o.scope == Scope::Runtime)
        .filter_map(|o| o.package.clone())
        .collect();
    if runtime.is_empty() {
        return;
    }
    for obs in observations.iter_mut() {
        if obs.scope != Scope::Development {
            continue;
        }
        if obs.package.as_ref().is_some_and(|p| runtime.contains(p)) {
            obs.scope = Scope::Runtime;
        }
    }
}

fn read_manifest(root: &Path, manifest: &str) -> HashMap<String, Scope> {
    let path = root.join(manifest);
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_string();
    let Ok(text) = std::fs::read_to_string(&path) else {
        return HashMap::new();
    };
    match name.as_str() {
        "package-lock.json" => npm_lock_scopes(&text),
        "package.json" => npm_package_scopes(&text),
        _ => HashMap::new(),
    }
}

/// npm resolves this for us: a package reachable only through `devDependencies`
/// is marked `"dev": true` in the lockfile, at whatever depth it sits.
pub fn npm_lock_scopes(text: &str) -> HashMap<String, Scope> {
    let Ok(lock): Result<Value, _> = serde_json::from_str(text) else {
        return HashMap::new();
    };
    let mut out: HashMap<String, Scope> = HashMap::new();
    // Lockfile v2/v3: a flat map keyed by install path.
    if let Some(packages) = lock.get("packages").and_then(Value::as_object) {
        for (path, entry) in packages {
            let Some(name) = package_name(path) else {
                continue;
            };
            record(&mut out, name, dev_flag(entry));
        }
    }
    // Lockfile v1: a tree keyed by package name.
    if let Some(deps) = lock.get("dependencies").and_then(Value::as_object) {
        walk_v1(deps, &mut out);
    }
    out
}

fn walk_v1(deps: &serde_json::Map<String, Value>, out: &mut HashMap<String, Scope>) {
    for (name, entry) in deps {
        record(out, name.clone(), dev_flag(entry));
        if let Some(nested) = entry.get("dependencies").and_then(Value::as_object) {
            walk_v1(nested, out);
        }
    }
}

/// `package.json` alone: only the declared dependencies, which is all a Target
/// without a lockfile can tell us.
pub fn npm_package_scopes(text: &str) -> HashMap<String, Scope> {
    let Ok(pkg): Result<Value, _> = serde_json::from_str(text) else {
        return HashMap::new();
    };
    let mut out = HashMap::new();
    for (field, scope) in [
        ("dependencies", Scope::Runtime),
        ("optionalDependencies", Scope::Runtime),
        ("peerDependencies", Scope::Runtime),
        ("devDependencies", Scope::Development),
    ] {
        if let Some(map) = pkg.get(field).and_then(Value::as_object) {
            for name in map.keys() {
                record(&mut out, name.clone(), scope == Scope::Development);
            }
        }
    }
    out
}

fn dev_flag(entry: &Value) -> bool {
    entry.get("dev").and_then(Value::as_bool).unwrap_or(false)
}

/// Runtime wins: the same package can appear twice in one lockfile, once
/// reachable from `dependencies` and once not.
fn record(out: &mut HashMap<String, Scope>, name: String, dev: bool) {
    let scope = if dev {
        Scope::Development
    } else {
        Scope::Runtime
    };
    match out.get(&name) {
        Some(Scope::Runtime) => {}
        _ => {
            out.insert(name, scope);
        }
    }
}

/// `node_modules/@scope/pkg/node_modules/dep` is a copy of `dep`. The root
/// entry, keyed by the empty string, is the Target itself and not a dependency.
fn package_name(path: &str) -> Option<String> {
    let (_, name) = path.rsplit_once("node_modules/")?;
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}
