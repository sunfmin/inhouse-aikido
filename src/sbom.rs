//! The dependency inventory, in the format everyone else asks for.
//!
//! CycloneDX, because it is what procurement, customers, and the other tools in
//! a supply chain already read. HQ writes what its last Scan actually saw, not
//! what a manifest says it might resolve to.

use crate::domain::Finding;
use crate::inventory::Package;
use serde_json::{json, Value};
use std::collections::HashMap;

pub const SPEC_VERSION: &str = "1.5";

/// A CycloneDX document for one Target's last scanned Revision.
///
/// `licenses` is what the Engines reported per package, which is often nothing;
/// a component with no known license simply carries none rather than a guess.
pub fn cyclonedx(
    target: &str,
    revision: &str,
    timestamp: &str,
    packages: &[Package],
    findings: &[&Finding],
) -> Value {
    let licenses = licenses_by_package(findings);
    let components: Vec<Value> = packages
        .iter()
        .map(|p| component(p, licenses.get(&p.name)))
        .collect();
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{"vendor": "inhouse-aikido", "name": "hq"}],
            "component": {
                "type": "application",
                "bom-ref": format!("{target}@{revision}"),
                "name": target,
                "version": revision,
            }
        },
        "components": components,
    })
}

fn component(p: &Package, license: Option<&String>) -> Value {
    let version = p.version.clone().unwrap_or_default();
    let mut out = json!({
        "type": "library",
        "bom-ref": purl(p),
        "name": p.name,
        "version": version,
        "purl": purl(p),
        // CycloneDX's own words: what ships is required, what only builds is
        // optional.
        "scope": match p.scope {
            crate::domain::Scope::Development => "optional",
            _ => "required",
        },
        "properties": [{"name": "hq:manifest", "value": p.manifest}],
    });
    if let Some(license) = license {
        out["licenses"] = json!([{"license": {"id": license}}]);
    }
    out
}

/// A package URL, which is how every other tool in the chain identifies a
/// component.
pub fn purl(p: &Package) -> String {
    let name = p
        .name
        .strip_prefix('@')
        .map(|rest| format!("%40{rest}"))
        .unwrap_or_else(|| p.name.clone());
    match &p.version {
        Some(v) if !v.is_empty() => format!("pkg:{}/{}@{}", p.ecosystem, name, v),
        _ => format!("pkg:{}/{}", p.ecosystem, name),
    }
}

/// The license each package was reported under, from its License Findings.
fn licenses_by_package(findings: &[&Finding]) -> HashMap<String, String> {
    findings
        .iter()
        .filter(|f| f.kind == crate::domain::FindingKind::License)
        .filter_map(|f| {
            f.package
                .clone()
                .map(|package| (package, f.fingerprint.problem_id.clone()))
        })
        .collect()
}
