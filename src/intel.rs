//! Exploitability intel: what is known about a CVE beyond how bad it looks.
//!
//! Severity is the Engine's opinion of the flaw. Whether anyone is actually
//! exploiting it is a different question, and a public one — FIRST publishes an
//! exploit-prediction score for nearly every CVE, and CISA publishes the list of
//! the ones already being used. HQ reads both, caches them, and ranks Findings
//! with them.
//!
//! Intel never fails a Scan. A source that is down leaves Findings ranked by
//! Engine severity alone, which is where they started.

use serde::Deserialize;
use std::collections::HashMap;

/// What the public sources say about one CVE.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct CveIntel {
    /// Probability of exploitation in the next 30 days, 0.0–1.0.
    pub epss: Option<f64>,
    /// Where that sits among all scored CVEs, 0.0–1.0.
    pub percentile: Option<f64>,
    /// Already exploited, per CISA's KEV catalogue.
    pub known_exploited: bool,
}

/// Where intel comes from. A port, so a Scan in a test never reaches the
/// network and an Operator can run HQ with no outbound access at all.
pub trait IntelSource: Send + Sync {
    fn name(&self) -> &str;

    /// Is there anything to ask? A source that answers nothing is not called at
    /// all, so it never leaves "nobody knows" in the cache for a real source to
    /// trip over later.
    fn answers(&self) -> bool {
        true
    }

    fn fetch(&self, cves: &[String]) -> Result<HashMap<String, CveIntel>, String>;
}

/// No outbound intel. Whatever is already cached still ranks Findings.
pub struct NoIntel;

impl IntelSource for NoIntel {
    fn name(&self) -> &str {
        "none"
    }

    fn answers(&self) -> bool {
        false
    }

    fn fetch(&self, _cves: &[String]) -> Result<HashMap<String, CveIntel>, String> {
        Ok(HashMap::new())
    }
}

const EPSS_API: &str = "https://api.first.org/data/v1/epss";
/// CISA's own published copy of the KEV catalogue. `cisa.gov` serves the same
/// document but answers a scanner's User-Agent with 403, so HQ reads the
/// repository CISA publishes it from. Override with `HQ_KEV_FEED`.
const KEV_FEED: &str =
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json";
/// The EPSS API takes a comma-separated list; keep the URL a sane length.
const EPSS_BATCH: usize = 100;

/// FIRST's EPSS scores plus CISA's Known Exploited Vulnerabilities catalogue.
pub struct PublicIntel {
    epss_api: String,
    kev_feed: String,
}

impl Default for PublicIntel {
    fn default() -> Self {
        Self::new()
    }
}

impl PublicIntel {
    pub fn new() -> Self {
        Self {
            epss_api: std::env::var("HQ_EPSS_API").unwrap_or_else(|_| EPSS_API.to_string()),
            kev_feed: std::env::var("HQ_KEV_FEED").unwrap_or_else(|_| KEV_FEED.to_string()),
        }
    }

    /// Point the sources somewhere else — a mirror, an air-gapped copy, or a
    /// test stub.
    pub fn with_endpoints(epss_api: &str, kev_feed: &str) -> Self {
        Self {
            epss_api: epss_api.to_string(),
            kev_feed: kev_feed.to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct EpssResponse {
    #[serde(default)]
    data: Vec<EpssRow>,
}

#[derive(Debug, Deserialize)]
struct EpssRow {
    cve: String,
    #[serde(default)]
    epss: Option<String>,
    #[serde(default)]
    percentile: Option<String>,
}

#[derive(Debug, Deserialize)]
struct KevCatalogue {
    #[serde(default)]
    vulnerabilities: Vec<KevEntry>,
}

#[derive(Debug, Deserialize)]
struct KevEntry {
    #[serde(rename = "cveID")]
    cve_id: String,
}

impl IntelSource for PublicIntel {
    fn name(&self) -> &str {
        "public"
    }

    fn fetch(&self, cves: &[String]) -> Result<HashMap<String, CveIntel>, String> {
        let mut out: HashMap<String, CveIntel> = HashMap::new();
        for chunk in cves.chunks(EPSS_BATCH) {
            let url = format!("{}?cve={}", self.epss_api, chunk.join(","));
            let body = get(&url)?;
            let parsed: EpssResponse =
                serde_json::from_str(&body).map_err(|e| format!("EPSS: {e}"))?;
            for row in parsed.data {
                let entry = out.entry(row.cve).or_default();
                entry.epss = row.epss.and_then(|s| s.parse().ok());
                entry.percentile = row.percentile.and_then(|s| s.parse().ok());
            }
        }
        // The KEV catalogue is one document, not a query. One fetch either way.
        let body = get(&self.kev_feed)?;
        let kev: KevCatalogue = serde_json::from_str(&body).map_err(|e| format!("KEV: {e}"))?;
        let listed: std::collections::HashSet<String> =
            kev.vulnerabilities.into_iter().map(|v| v.cve_id).collect();
        for cve in cves {
            if listed.contains(cve) {
                out.entry(cve.clone()).or_default().known_exploited = true;
            }
        }
        Ok(out)
    }
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

/// The CVE ids worth asking about. Engines report plenty of problem ids that
/// are not CVEs — rule names, licence names — and those have no intel.
pub fn cve_ids(problem_ids: impl Iterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = problem_ids.filter(|id| is_cve(id)).collect();
    out.sort();
    out.dedup();
    out
}

/// `CVE-2021-44228`, and nothing that merely starts that way.
pub fn is_cve(id: &str) -> bool {
    let mut parts = id.split('-');
    if !parts.next().is_some_and(|p| p.eq_ignore_ascii_case("CVE")) {
        return false;
    }
    let Some(year) = parts.next() else {
        return false;
    };
    let Some(number) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && year.len() == 4
        && year.chars().all(|c| c.is_ascii_digit())
        && number.len() >= 4
        && number.chars().all(|c| c.is_ascii_digit())
}
