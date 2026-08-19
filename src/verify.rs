//! Is the leaked credential still live?
//!
//! A key that was rotated last year and a key somebody can use right now look
//! identical in a Scan report, and they are not the same problem. HQ asks the
//! credential's own provider — one read-only identity call, the cheapest
//! question each API has — and keeps only the answer.
//!
//! What HQ never does: store the credential, log it, put it in a Check Run, or
//! make any call that could change the account it belongs to.

use crate::domain::Validity;

/// Somebody who can tell whether a credential still authenticates.
pub trait SecretVerifier: Send + Sync {
    fn name(&self) -> &str;

    /// Is verification switched on at all? Off is the default: HQ does not send
    /// a Target's credentials to a third party unless an Operator says to.
    fn enabled(&self) -> bool {
        true
    }

    /// `rule` is the Engine's rule id, `value` the credential. Anything the
    /// registry does not recognise comes back Unverified.
    fn check(&self, rule: &str, value: &str) -> Validity;
}

/// Verification off. Every secret stays Unverified, which is how HQ behaved
/// before there was such a thing.
pub struct NoVerification;

impl SecretVerifier for NoVerification {
    fn name(&self) -> &str {
        "off"
    }

    fn enabled(&self) -> bool {
        false
    }

    fn check(&self, _rule: &str, _value: &str) -> Validity {
        Validity::Unverified
    }
}

/// One credential type HQ knows how to ask about.
pub struct Provider {
    /// What to call it in a log.
    pub name: &'static str,
    /// Does this credential belong to this provider? Matched on the token's own
    /// shape, not on the Engine's rule name, because rule names differ between
    /// Engines and versions while the prefix is the provider's own contract.
    pub matches: fn(&str) -> bool,
    /// The read-only identity endpoint, and how to present the credential.
    pub endpoint: fn(&ProviderEndpoints) -> Request,
}

/// Where each provider's identity call goes. Overridable so an Operator can
/// point at an enterprise host, and so tests never talk to a real provider.
#[derive(Debug, Clone)]
pub struct ProviderEndpoints {
    pub github: String,
    pub npm: String,
    pub slack: String,
    pub openai: String,
}

impl Default for ProviderEndpoints {
    fn default() -> Self {
        Self {
            github: env_or("HQ_VERIFY_GITHUB", "https://api.github.com/user"),
            npm: env_or("HQ_VERIFY_NPM", "https://registry.npmjs.org/-/whoami"),
            slack: env_or("HQ_VERIFY_SLACK", "https://slack.com/api/auth.test"),
            openai: env_or("HQ_VERIFY_OPENAI", "https://api.openai.com/v1/models"),
        }
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// One identity call: never anything but a read.
#[derive(Debug, Clone)]
pub struct Request {
    pub url: String,
    pub header: &'static str,
    /// `Bearer `, `token `, or empty.
    pub prefix: &'static str,
    /// Some APIs answer 200 with `{"ok": false}` rather than 401.
    pub ok_field: Option<&'static str>,
}

fn github(e: &ProviderEndpoints) -> Request {
    Request {
        url: e.github.clone(),
        header: "Authorization",
        prefix: "Bearer ",
        ok_field: None,
    }
}

fn npm(e: &ProviderEndpoints) -> Request {
    Request {
        url: e.npm.clone(),
        header: "Authorization",
        prefix: "Bearer ",
        ok_field: None,
    }
}

fn slack(e: &ProviderEndpoints) -> Request {
    Request {
        url: e.slack.clone(),
        header: "Authorization",
        prefix: "Bearer ",
        // auth.test answers 200 either way and says so in the body.
        ok_field: Some("ok"),
    }
}

fn openai(e: &ProviderEndpoints) -> Request {
    Request {
        url: e.openai.clone(),
        header: "Authorization",
        prefix: "Bearer ",
        ok_field: None,
    }
}

/// The credential types HQ can check. Adding another is one entry.
pub fn providers() -> Vec<Provider> {
    vec![
        Provider {
            name: "github",
            matches: |v| {
                v.starts_with("ghp_")
                    || v.starts_with("gho_")
                    || v.starts_with("ghs_")
                    || v.starts_with("github_pat_")
            },
            endpoint: github,
        },
        Provider {
            name: "npm",
            matches: |v| v.starts_with("npm_"),
            endpoint: npm,
        },
        Provider {
            name: "slack",
            matches: |v| v.starts_with("xoxb-") || v.starts_with("xoxp-") || v.starts_with("xoxa-"),
            endpoint: slack,
        },
        Provider {
            name: "openai",
            matches: |v| v.starts_with("sk-") && v.len() > 20,
            endpoint: openai,
        },
    ]
}

/// Asks the real providers.
pub struct ProviderVerifier {
    endpoints: ProviderEndpoints,
    providers: Vec<Provider>,
}

impl Default for ProviderVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderVerifier {
    pub fn new() -> Self {
        Self {
            endpoints: ProviderEndpoints::default(),
            providers: providers(),
        }
    }

    pub fn with_endpoints(endpoints: ProviderEndpoints) -> Self {
        Self {
            endpoints,
            providers: providers(),
        }
    }

    /// Which provider a credential belongs to, if HQ knows.
    pub fn provider_for(&self, value: &str) -> Option<&Provider> {
        self.providers.iter().find(|p| (p.matches)(value))
    }
}

impl SecretVerifier for ProviderVerifier {
    fn name(&self) -> &str {
        "providers"
    }

    fn check(&self, _rule: &str, value: &str) -> Validity {
        let Some(provider) = self.provider_for(value) else {
            return Validity::Unverified;
        };
        let request = (provider.endpoint)(&self.endpoints);
        ask(&request, value)
    }
}

/// One GET, with the credential presented the way its provider expects.
///
/// 401/403 is the provider saying the credential is dead. Anything else that
/// goes wrong — a timeout, a 500, a proxy — is HQ not knowing, which is
/// Unverified. Never Inactive: calling a live key dead is the one answer that
/// would let a real incident through.
fn ask(request: &Request, value: &str) -> Validity {
    let credential = format!("{}{}", request.prefix, value);
    let response = ureq::get(&request.url)
        .header(request.header, &credential)
        .header("User-Agent", "inhouse-aikido-hq")
        .header("Accept", "application/json")
        .call();
    match response {
        Ok(mut ok) => match request.ok_field {
            None => Validity::Active,
            Some(field) => match ok.body_mut().read_to_string() {
                Ok(body) => match serde_json::from_str::<serde_json::Value>(&body) {
                    Ok(json) if json.get(field).and_then(|v| v.as_bool()) == Some(true) => {
                        Validity::Active
                    }
                    Ok(_) => Validity::Inactive,
                    Err(_) => Validity::Unverified,
                },
                Err(_) => Validity::Unverified,
            },
        },
        Err(ureq::Error::StatusCode(401 | 403)) => Validity::Inactive,
        // A provider HQ cannot reach has told us nothing.
        Err(_) => Validity::Unverified,
    }
}
