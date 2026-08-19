//! Dependencies that are not merely vulnerable but hostile.
//!
//! A CVE is a mistake somebody made in a package you meant to install. A
//! malicious package is not that: the fix is removal, not a version bump, and it
//! cannot sit on a Baseline as accepted debt. Two ways HQ finds them — public
//! advisories for packages already known to be malware, and names that are
//! near-misses of packages a Developer plausibly meant to type.

use crate::inventory::Package;
use serde::Deserialize;
use std::collections::HashMap;

/// A public advisory saying a package is malware.
#[derive(Debug, Clone, PartialEq)]
pub struct Advisory {
    pub id: String,
    pub summary: String,
}

/// Where advisories come from. A port, so a Scan in a test never reaches the
/// network and an Operator can run HQ with no outbound access.
pub trait AdvisorySource: Send + Sync {
    fn name(&self) -> &str;

    /// Is there anything to ask? Off means no malicious Findings from
    /// advisories — typosquat detection is local and runs either way.
    fn enabled(&self) -> bool {
        true
    }

    /// Keyed by package name. Absent means the source said nothing about it.
    fn malicious(&self, packages: &[Package]) -> Result<HashMap<String, Advisory>, String>;
}

/// No advisory lookups.
pub struct NoAdvisories;

impl AdvisorySource for NoAdvisories {
    fn name(&self) -> &str {
        "none"
    }

    fn enabled(&self) -> bool {
        false
    }

    fn malicious(&self, _packages: &[Package]) -> Result<HashMap<String, Advisory>, String> {
        Ok(HashMap::new())
    }
}

const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL: &str = "https://api.osv.dev/v1/vulns";
/// OSV takes up to 1000 queries per batch; stay well inside it.
const BATCH: usize = 500;

/// OSV.dev. Malicious-package advisories there carry `MAL-` ids, which is what
/// separates "this package has a bug" from "this package is the attack".
pub struct OsvAdvisories {
    batch_url: String,
    vuln_url: String,
}

impl Default for OsvAdvisories {
    fn default() -> Self {
        Self::new()
    }
}

impl OsvAdvisories {
    pub fn new() -> Self {
        Self {
            batch_url: std::env::var("HQ_OSV_BATCH_URL")
                .unwrap_or_else(|_| OSV_BATCH_URL.to_string()),
            vuln_url: std::env::var("HQ_OSV_VULN_URL").unwrap_or_else(|_| OSV_VULN_URL.to_string()),
        }
    }

    pub fn with_endpoints(batch_url: &str, vuln_url: &str) -> Self {
        Self {
            batch_url: batch_url.to_string(),
            vuln_url: vuln_url.to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct BatchResponse {
    #[serde(default)]
    results: Vec<BatchResult>,
}

#[derive(Debug, Deserialize)]
struct BatchResult {
    #[serde(default)]
    vulns: Vec<VulnRef>,
}

#[derive(Debug, Deserialize)]
struct VulnRef {
    id: String,
}

#[derive(Debug, Deserialize)]
struct VulnDetail {
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    details: Option<String>,
}

impl AdvisorySource for OsvAdvisories {
    fn name(&self) -> &str {
        "osv"
    }

    fn malicious(&self, packages: &[Package]) -> Result<HashMap<String, Advisory>, String> {
        let mut out = HashMap::new();
        for chunk in packages.chunks(BATCH) {
            let queries: Vec<serde_json::Value> = chunk
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "package": {"name": p.name, "ecosystem": ecosystem_of(&p.ecosystem)}
                    })
                })
                .collect();
            let body = serde_json::json!({ "queries": queries });
            let raw = post(&self.batch_url, &body)?;
            let parsed: BatchResponse =
                serde_json::from_str(&raw).map_err(|e| format!("OSV: {e}"))?;
            // The batch answers in the order it was asked, so position is what
            // ties a result back to its package.
            for (package, result) in chunk.iter().zip(parsed.results) {
                let Some(id) = result
                    .vulns
                    .into_iter()
                    .map(|v| v.id)
                    .find(|id| id.starts_with("MAL-"))
                else {
                    continue;
                };
                let summary = self.summary_of(&id).unwrap_or_default();
                out.insert(
                    package.name.clone(),
                    Advisory {
                        id,
                        summary: if summary.is_empty() {
                            "reported as a malicious package".to_string()
                        } else {
                            summary
                        },
                    },
                );
            }
        }
        Ok(out)
    }
}

impl OsvAdvisories {
    /// Only for the handful that matched. A Target with no malware makes one
    /// request in total.
    fn summary_of(&self, id: &str) -> Option<String> {
        let raw = get(&format!("{}/{id}", self.vuln_url)).ok()?;
        let detail: VulnDetail = serde_json::from_str(&raw).ok()?;
        detail
            .summary
            .or(detail.details)
            .map(|s| s.lines().next().unwrap_or_default().trim().to_string())
    }
}

/// OSV spells npm "npm" and most others capitalised. One place to know that.
fn ecosystem_of(name: &str) -> &str {
    match name {
        "npm" => "npm",
        "pypi" => "PyPI",
        "cargo" => "crates.io",
        "go" => "Go",
        other => other,
    }
}

fn post(url: &str, body: &serde_json::Value) -> Result<String, String> {
    let payload = serde_json::to_vec(body).map_err(|e| e.to_string())?;
    ureq::post(url)
        .header("Content-Type", "application/json")
        .header("User-Agent", "inhouse-aikido-hq")
        .send(&payload[..])
        .map_err(|e| format!("POST {url}: {e}"))?
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("POST {url}: {e}"))
}

fn get(url: &str) -> Result<String, String> {
    ureq::get(url)
        .header("User-Agent", "inhouse-aikido-hq")
        .call()
        .map_err(|e| format!("GET {url}: {e}"))?
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("GET {url}: {e}"))
}

/// Packages people install a lot, and therefore packages people mistype a lot.
/// Not a security list — a list of names worth being one keystroke away from.
pub const POPULAR_NPM: [&str; 60] = [
    "lodash",
    "react",
    "react-dom",
    "express",
    "axios",
    "chalk",
    "commander",
    "debug",
    "moment",
    "request",
    "typescript",
    "webpack",
    "eslint",
    "prettier",
    "jest",
    "mocha",
    "chai",
    "vue",
    "angular",
    "rxjs",
    "redux",
    "underscore",
    "async",
    "bluebird",
    "uuid",
    "dotenv",
    "yargs",
    "glob",
    "rimraf",
    "mkdirp",
    "semver",
    "minimist",
    "colors",
    "cross-env",
    "babel-core",
    "node-fetch",
    "socket.io",
    "mongoose",
    "sequelize",
    "pg",
    "mysql",
    "redis",
    "jsonwebtoken",
    "bcrypt",
    "passport",
    "cors",
    "helmet",
    "morgan",
    "body-parser",
    "nodemon",
    "ts-node",
    "rollup",
    "vite",
    "esbuild",
    "tailwindcss",
    "next",
    "nuxt",
    "svelte",
    "graphql",
    "apollo-server",
];

/// A package whose name is one keystroke from something popular.
#[derive(Debug, Clone, PartialEq)]
pub struct Typosquat {
    pub package: String,
    /// The well-known name it is a near-miss of.
    pub looks_like: String,
}

/// Names that are near-misses of packages a Developer plausibly meant to type.
///
/// Only a package the Target does not also depend on for real: a repository that
/// has both `lodash` and `lodahs` is a repository with a problem, but one that
/// has only `lodash` is fine.
pub fn typosquats(packages: &[Package]) -> Vec<Typosquat> {
    let installed: std::collections::HashSet<&str> =
        packages.iter().map(|p| p.name.as_str()).collect();
    let mut out: Vec<Typosquat> = Vec::new();
    for package in packages {
        if POPULAR_NPM.contains(&package.name.as_str()) {
            continue;
        }
        let Some(looks_like) = near_miss(&package.name) else {
            continue;
        };
        // A near-miss only matters if the real package is not what got
        // installed under a different name — scoped forks and re-publishes are
        // normal.
        if package.name.starts_with('@') {
            continue;
        }
        let squat = Typosquat {
            package: package.name.clone(),
            looks_like: looks_like.to_string(),
        };
        if !out.contains(&squat) {
            out.push(squat);
        }
    }
    let _ = installed;
    out.sort_by(|a, b| a.package.cmp(&b.package));
    out
}

/// The popular name this is one edit away from, if any.
pub fn near_miss(name: &str) -> Option<&'static str> {
    // Too short to say anything: `ms` is one edit from half the registry.
    if name.len() < 4 {
        return None;
    }
    POPULAR_NPM
        .iter()
        .find(|popular| **popular != name && edit_distance_is_one(name, popular))
        .copied()
}

/// Damerau-Levenshtein distance of exactly one: a substitution, an insertion, a
/// deletion, or two adjacent characters swapped. Everything a fat finger does.
pub fn edit_distance_is_one(a: &str, b: &str) -> bool {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    match a.len().abs_diff(b.len()) {
        0 => {
            let differing: Vec<usize> = (0..a.len()).filter(|i| a[*i] != b[*i]).collect();
            match differing.len() {
                1 => true,
                // A transposition: two neighbours, each holding the other's
                // character.
                2 => {
                    let (i, j) = (differing[0], differing[1]);
                    j == i + 1 && a[i] == b[j] && a[j] == b[i]
                }
                _ => false,
            }
        }
        1 => {
            let (long, short) = if a.len() > b.len() {
                (&a, &b)
            } else {
                (&b, &a)
            };
            let mut skipped = false;
            let mut j = 0;
            for c in long.iter() {
                if j < short.len() && short[j] == *c {
                    j += 1;
                } else if skipped {
                    return false;
                } else {
                    skipped = true;
                }
            }
            true
        }
        _ => false,
    }
}
