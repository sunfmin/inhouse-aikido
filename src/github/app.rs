//! HQ's identity on GitHub: the App.
//!
//! HQ never acts as a person. It signs a short-lived JWT with the App's private
//! key, exchanges that for an installation access token, and uses the token for
//! everything it does to a Target. Tokens are cached until shortly before the
//! expiry GitHub reports.
//!
//! See ADR 0019 (HQ is a GitHub App) and ADR 0020 (HQ stays synchronous).

use serde::Deserialize;
use std::collections::HashMap;
use std::fmt;

const DEFAULT_API_BASE: &str = "https://api.github.com";
const USER_AGENT: &str = "inhouse-aikido-hq";
const API_VERSION: &str = "2022-11-28";

/// GitHub rejects an App JWT whose lifetime exceeds ten minutes.
const JWT_LIFETIME_SECS: u64 = 540;
/// Backdate `iat` to tolerate clock skew between HQ and GitHub.
const JWT_BACKDATE_SECS: u64 = 60;
/// Renew an installation token this many seconds before GitHub's expiry.
const TOKEN_REFRESH_MARGIN_SECS: i64 = 60;

/// The App's credentials. Never printed, never persisted.
#[derive(Clone)]
pub struct AppConfig {
    pub app_id: String,
    pub api_base: String,
    private_key_pem: String,
}

impl fmt::Debug for AppConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppConfig")
            .field("app_id", &self.app_id)
            .field("api_base", &self.api_base)
            .field("private_key_pem", &"<redacted>")
            .finish()
    }
}

impl AppConfig {
    pub fn new(
        app_id: impl Into<String>,
        private_key_pem: impl Into<String>,
        api_base: impl Into<String>,
    ) -> Self {
        Self {
            app_id: app_id.into(),
            private_key_pem: private_key_pem.into(),
            api_base: api_base.into(),
        }
    }

    /// Read the App's credentials from the environment. The private key may be
    /// given inline or as a path to the `.pem` GitHub hands out.
    pub fn from_env() -> Result<Self, String> {
        let app_id = std::env::var("HQ_GITHUB_APP_ID").map_err(|_| {
            "HQ_GITHUB_APP_ID is not set — HQ needs the App's numeric id to sign a JWT".to_string()
        })?;
        if app_id.trim().is_empty() {
            return Err("HQ_GITHUB_APP_ID is empty".into());
        }
        let key = match (
            std::env::var("HQ_GITHUB_PRIVATE_KEY"),
            std::env::var("HQ_GITHUB_PRIVATE_KEY_PATH"),
        ) {
            (Ok(pem), _) if !pem.trim().is_empty() => pem,
            (_, Ok(path)) => std::fs::read_to_string(&path)
                .map_err(|e| format!("cannot read the App private key at {path}: {e}"))?,
            _ => {
                return Err("neither HQ_GITHUB_PRIVATE_KEY nor HQ_GITHUB_PRIVATE_KEY_PATH is set \
                            — HQ needs the App's private key"
                    .into())
            }
        };
        let api_base =
            std::env::var("HQ_GITHUB_API_BASE").unwrap_or_else(|_| DEFAULT_API_BASE.to_string());
        Ok(Self::new(app_id.trim(), key, api_base))
    }
}

#[derive(Debug, Deserialize)]
pub struct Account {
    pub login: String,
}

#[derive(Debug, Deserialize)]
pub struct AppIdentity {
    pub id: u64,
    pub name: String,
    pub slug: Option<String>,
    pub owner: Option<Account>,
}

#[derive(Debug, Deserialize)]
pub struct Installation {
    pub id: u64,
    pub account: Option<Account>,
    pub repository_selection: Option<String>,
}

#[derive(Deserialize)]
struct Repository {
    full_name: String,
}

#[derive(Deserialize)]
struct RepositoryPage {
    repositories: Vec<Repository>,
}

#[derive(Deserialize)]
struct AccessToken {
    token: String,
    expires_at: String,
}

#[derive(serde::Serialize)]
struct JwtClaims {
    iat: u64,
    exp: u64,
    iss: String,
}

/// Mint the App JWT GitHub accepts on the `/app` routes.
pub fn mint_jwt(app_id: &str, private_key_pem: &str, now_unix: u64) -> Result<String, String> {
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .map_err(|e| format!("the App private key is not a usable RSA PEM: {e}"))?;
    let claims = JwtClaims {
        iat: now_unix.saturating_sub(JWT_BACKDATE_SECS),
        exp: now_unix + JWT_LIFETIME_SECS,
        iss: app_id.to_string(),
    };
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
        &claims,
        &key,
    )
    .map_err(|e| format!("could not sign the App JWT: {e}"))
}

/// A cached installation token is usable while it has more than the refresh
/// margin left. The margin, not a hard-coded lifetime, is what HQ relies on.
pub fn token_is_usable(expires_at_unix: i64, now_unix: i64) -> bool {
    expires_at_unix - now_unix > TOKEN_REFRESH_MARGIN_SECS
}

/// Parse the RFC 3339 instant GitHub returns with an installation token.
pub fn parse_expiry(s: &str) -> Result<i64, String> {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map(|t| t.unix_timestamp())
        .map_err(|e| format!("GitHub returned an unparseable token expiry {s:?}: {e}"))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Clone)]
struct CachedToken {
    token: String,
    expires_at_unix: i64,
}

/// Authenticates HQ to GitHub as the App and hands out installation tokens.
pub struct AppAuth {
    config: AppConfig,
    agent: ureq::Agent,
    tokens: HashMap<u64, CachedToken>,
}

impl fmt::Debug for AppAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppAuth")
            .field("config", &self.config)
            .field("cached_tokens", &self.tokens.len())
            .finish()
    }
}

impl AppAuth {
    pub fn new(config: AppConfig) -> Self {
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .new_agent();
        Self {
            config,
            agent,
            tokens: HashMap::new(),
        }
    }

    pub fn from_env() -> Result<Self, String> {
        Ok(Self::new(AppConfig::from_env()?))
    }

    fn jwt(&self) -> Result<String, String> {
        mint_jwt(
            &self.config.app_id,
            &self.config.private_key_pem,
            now_unix(),
        )
    }

    /// The App HQ is authenticating as.
    pub fn app_identity(&self) -> Result<AppIdentity, String> {
        let body = self.get("/app", &format!("Bearer {}", self.jwt()?))?;
        serde_json::from_str(&body).map_err(|e| format!("unexpected /app response: {e}"))
    }

    /// Every installation of the App.
    pub fn installations(&self) -> Result<Vec<Installation>, String> {
        let body = self.get("/app/installations", &format!("Bearer {}", self.jwt()?))?;
        serde_json::from_str(&body)
            .map_err(|e| format!("unexpected /app/installations response: {e}"))
    }

    /// The installation covering a Target, so HQ knows which token to use for it.
    pub fn installation_for_repo(&self, repo: &str) -> Result<Installation, String> {
        let (owner, name) = repo
            .split_once('/')
            .ok_or_else(|| format!("{repo} is not an owner/name repository"))?;
        let path = format!("/repos/{owner}/{name}/installation");
        let body = self.get(&path, &format!("Bearer {}", self.jwt()?))?;
        serde_json::from_str(&body).map_err(|e| format!("unexpected {path} response: {e}"))
    }

    /// An installation access token, minted on first use and reused until it is
    /// close to the expiry GitHub reported.
    pub fn installation_token(&mut self, installation_id: u64) -> Result<String, String> {
        let now = now_unix() as i64;
        if let Some(cached) = self.tokens.get(&installation_id) {
            if token_is_usable(cached.expires_at_unix, now) {
                return Ok(cached.token.clone());
            }
        }
        let path = format!("/app/installations/{installation_id}/access_tokens");
        let body = self.post(&path, &format!("Bearer {}", self.jwt()?))?;
        let minted: AccessToken =
            serde_json::from_str(&body).map_err(|e| format!("unexpected {path} response: {e}"))?;
        let expires_at_unix = parse_expiry(&minted.expires_at)?;
        self.tokens.insert(
            installation_id,
            CachedToken {
                token: minted.token.clone(),
                expires_at_unix,
            },
        );
        Ok(minted.token)
    }

    /// The repositories one installation covers.
    pub fn installation_repos(&mut self, installation_id: u64) -> Result<Vec<String>, String> {
        let token = self.installation_token(installation_id)?;
        let body = self.get("/installation/repositories", &format!("token {token}"))?;
        let page: RepositoryPage = serde_json::from_str(&body)
            .map_err(|e| format!("unexpected /installation/repositories response: {e}"))?;
        Ok(page.repositories.into_iter().map(|r| r.full_name).collect())
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.config.api_base.trim_end_matches('/'), path)
    }

    fn get(&self, path: &str, authorization: &str) -> Result<String, String> {
        let mut res = self
            .agent
            .get(self.url(path))
            .header("Authorization", authorization)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", API_VERSION)
            .header("User-Agent", USER_AGENT)
            .call()
            .map_err(|e| format!("GitHub request to {path} failed: {e}"))?;
        finish(path, &mut res)
    }

    fn post(&self, path: &str, authorization: &str) -> Result<String, String> {
        let mut res = self
            .agent
            .post(self.url(path))
            .header("Authorization", authorization)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", API_VERSION)
            .header("User-Agent", USER_AGENT)
            .send_empty()
            .map_err(|e| format!("GitHub request to {path} failed: {e}"))?;
        finish(path, &mut res)
    }
}

fn finish(path: &str, res: &mut ureq::http::Response<ureq::Body>) -> Result<String, String> {
    let status = res.status().as_u16();
    let body = res
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("reading the GitHub response to {path}: {e}"))?;
    if !(200..300).contains(&status) {
        return Err(github_error(path, status, &body));
    }
    Ok(body)
}

/// GitHub's own message, which says useful things like "A JSON web token could
/// not be decoded". Never includes the request, which carries the credential.
fn github_error(path: &str, status: u16, body: &str) -> String {
    let message = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("message")
                .and_then(|m| m.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| body.chars().take(200).collect());
    format!("GitHub {status} on {path}: {message}")
}
