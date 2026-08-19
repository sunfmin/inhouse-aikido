//! HQ authenticates to GitHub as the App: a signed JWT on the /app routes, an
//! installation token everywhere else, cached until it nears GitHub's expiry.
//!
//! These tests never reach the network. The API-shaped ones speak to a stub
//! listener on localhost; the one test that talks to real GitHub is ignored
//! unless App credentials are in the environment.

use hq::github::app::{mint_jwt, parse_expiry, token_is_usable, AppAuth, AppConfig};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const PKCS8_KEY: &str = include_str!("fixtures/app/test-app-key.pem");
const PKCS1_KEY: &str = include_str!("fixtures/app/test-app-key.pkcs1.pem");
const PUBLIC_KEY: &str = include_str!("fixtures/app/test-app-key.pub.pem");

#[derive(serde::Deserialize)]
struct Claims {
    iat: u64,
    exp: u64,
    iss: String,
}

fn verify(token: &str) -> Claims {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = false;
    validation.required_spec_claims.clear();
    decode::<Claims>(
        token,
        &DecodingKey::from_rsa_pem(PUBLIC_KEY.as_bytes()).expect("public key"),
        &validation,
    )
    .expect("the App JWT verifies against the App's public key")
    .claims
}

#[test]
fn app_jwt_is_signed_with_the_app_key_and_names_the_app() {
    for key in [PKCS8_KEY, PKCS1_KEY] {
        let token = mint_jwt("123456", key, 1_700_000_000).expect("mint");
        let claims = verify(&token);
        assert_eq!(claims.iss, "123456");
        // Backdated so a slow clock on our side is not an instant rejection.
        assert!(claims.iat < 1_700_000_000);
        // GitHub rejects anything longer than ten minutes.
        assert!(claims.exp > 1_700_000_000);
        assert!(claims.exp - claims.iat <= 600, "jwt lifetime under 10 minutes");
    }
}

#[test]
fn a_malformed_private_key_is_an_operator_error_not_a_panic() {
    let err = mint_jwt("123456", "-----BEGIN RSA PRIVATE KEY-----\nnope\n", 0).unwrap_err();
    assert!(
        err.contains("private key"),
        "error should name the private key, got {err:?}"
    );
}

#[test]
fn credentials_come_from_the_environment_and_say_what_is_missing() {
    // One test owns the process environment so parallel tests cannot race on it.
    for var in [
        "HQ_GITHUB_APP_ID",
        "HQ_GITHUB_PRIVATE_KEY",
        "HQ_GITHUB_PRIVATE_KEY_PATH",
        "HQ_GITHUB_API_BASE",
    ] {
        std::env::remove_var(var);
    }
    let err = AppConfig::from_env().unwrap_err();
    assert!(err.contains("HQ_GITHUB_APP_ID"), "got {err:?}");

    std::env::set_var("HQ_GITHUB_APP_ID", "42");
    let err = AppConfig::from_env().unwrap_err();
    assert!(err.contains("HQ_GITHUB_PRIVATE_KEY"), "got {err:?}");

    std::env::set_var("HQ_GITHUB_PRIVATE_KEY_PATH", "/definitely/not/here.pem");
    let err = AppConfig::from_env().unwrap_err();
    assert!(err.contains("/definitely/not/here.pem"), "got {err:?}");

    std::env::set_var("HQ_GITHUB_PRIVATE_KEY", PKCS8_KEY);
    let cfg = AppConfig::from_env().expect("inline key wins");
    assert_eq!(cfg.app_id, "42");
    assert_eq!(cfg.api_base, "https://api.github.com");

    // The key never shows up in a debug print.
    let shown = format!("{cfg:?}");
    assert!(shown.contains("<redacted>"));
    assert!(!shown.contains("PRIVATE KEY"));

    for var in ["HQ_GITHUB_APP_ID", "HQ_GITHUB_PRIVATE_KEY"] {
        std::env::remove_var(var);
    }
}

#[test]
fn a_cached_token_is_reused_until_it_nears_the_expiry_github_reported() {
    // 3600s of life left: reuse. 30s left: renew, because a Scan can outlive it.
    assert!(token_is_usable(1_000_000, 1_000_000 - 3600));
    assert!(!token_is_usable(1_000_000, 1_000_000 - 30));
    assert!(!token_is_usable(1_000_000, 1_000_001));
}

#[test]
fn token_expiry_is_read_from_githubs_response() {
    assert_eq!(parse_expiry("1970-01-01T00:01:00Z").unwrap(), 60);
    assert!(parse_expiry("next tuesday").is_err());
}

// --- API-shaped tests against a stub listener -------------------------------

struct Stub {
    base: String,
    seen: Arc<Mutex<Vec<(String, String)>>>,
}

impl Stub {
    fn paths(&self) -> Vec<String> {
        self.seen.lock().unwrap().iter().map(|(p, _)| p.clone()).collect()
    }
    fn auth_for(&self, path: &str) -> String {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, a)| a.clone())
            .unwrap_or_default()
    }
    fn hits(&self, path: &str) -> usize {
        self.paths().iter().filter(|p| p.as_str() == path).count()
    }
}

/// A stand-in for the GitHub API. `first_token_expiry` lets a test hand back a
/// token that is already stale, to prove HQ renews rather than reusing it.
fn stub(first_token_expiry: &'static str) -> Stub {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    let token_calls = AtomicUsize::new(0);

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut sock) = stream else { continue };
            let mut reader = BufReader::new(sock.try_clone().unwrap());
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).is_err() {
                continue;
            }
            let path = request_line
                .split_whitespace()
                .nth(1)
                .unwrap_or("/")
                .to_string();
            let mut authorization = String::new();
            loop {
                let mut header = String::new();
                match reader.read_line(&mut header) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
                if header.trim().is_empty() {
                    break;
                }
                let lower = header.to_ascii_lowercase();
                if let Some(v) = lower.strip_prefix("authorization:") {
                    let n = header.len() - v.len();
                    authorization = header[n..].trim().to_string();
                }
            }
            log.lock().unwrap().push((path.clone(), authorization));

            let (status, body) = match path.as_str() {
                "/app" => (
                    200,
                    r#"{"id":42,"name":"In-house HQ","slug":"inhouse-hq","owner":{"login":"theplant"}}"#
                        .to_string(),
                ),
                "/app/installations" => (
                    200,
                    r#"[{"id":7,"account":{"login":"theplant"},"repository_selection":"selected"}]"#
                        .to_string(),
                ),
                "/app/installations/7/access_tokens" => {
                    let n = token_calls.fetch_add(1, Ordering::SeqCst);
                    let expiry = if n == 0 {
                        first_token_expiry
                    } else {
                        "2099-01-01T00:00:00Z"
                    };
                    (
                        201,
                        format!(r#"{{"token":"ghs_installation_{n}","expires_at":"{expiry}"}}"#),
                    )
                }
                "/installation/repositories" => (
                    200,
                    r#"{"total_count":2,"repositories":[{"full_name":"theplant/web"},{"full_name":"theplant/worker"}]}"#
                        .to_string(),
                ),
                "/repos/theplant/web/installation" => (
                    200,
                    r#"{"id":7,"account":{"login":"theplant"},"repository_selection":"selected"}"#
                        .to_string(),
                ),
                _ => (404, r#"{"message":"Not Found"}"#.to_string()),
            };
            let response = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(response.as_bytes());
            let _ = sock.flush();
            let _ = sock.shutdown(std::net::Shutdown::Write);
        }
    });

    Stub { base, seen }
}

fn auth_against(stub: &Stub) -> AppAuth {
    AppAuth::new(AppConfig::new("42", PKCS8_KEY, stub.base.clone()))
}

#[test]
fn whoami_and_installations_read_the_api_as_the_app() {
    let stub = stub("2099-01-01T00:00:00Z");
    let mut auth = auth_against(&stub);

    let app = auth.app_identity().expect("GET /app");
    assert_eq!(app.id, 42);
    assert_eq!(app.slug.as_deref(), Some("inhouse-hq"));
    assert_eq!(app.owner.unwrap().login, "theplant");

    let installs = auth.installations().expect("GET /app/installations");
    assert_eq!(installs.len(), 1);
    assert_eq!(installs[0].id, 7);
    assert_eq!(installs[0].account.as_ref().unwrap().login, "theplant");

    let repos = auth.installation_repos(7).expect("installation repositories");
    assert_eq!(repos, vec!["theplant/web", "theplant/worker"]);

    let install = auth
        .installation_for_repo("theplant/web")
        .expect("installation for a Target");
    assert_eq!(install.id, 7);

    // App routes carry the JWT; anything scoped to an installation carries the
    // installation token instead.
    let app_auth = stub.auth_for("/app");
    assert!(app_auth.starts_with("Bearer "), "got {app_auth:?}");
    verify(app_auth.trim_start_matches("Bearer "));
    assert_eq!(
        stub.auth_for("/installation/repositories"),
        "token ghs_installation_0"
    );
}

#[test]
fn an_installation_token_is_minted_once_and_reused() {
    let stub = stub("2099-01-01T00:00:00Z");
    let mut auth = auth_against(&stub);

    let first = auth.installation_token(7).unwrap();
    let second = auth.installation_token(7).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        stub.hits("/app/installations/7/access_tokens"),
        1,
        "a live token is reused, not re-minted"
    );
}

#[test]
fn a_token_that_is_already_expiring_is_renewed() {
    let stub = stub("2000-01-01T00:00:00Z");
    let mut auth = auth_against(&stub);

    let first = auth.installation_token(7).unwrap();
    let second = auth.installation_token(7).unwrap();
    assert_ne!(first, second, "a stale token is not handed out again");
    assert_eq!(stub.hits("/app/installations/7/access_tokens"), 2);
}

#[test]
fn githubs_own_message_survives_an_error_status() {
    let stub = stub("2099-01-01T00:00:00Z");
    let auth = AppAuth::new(AppConfig::new("42", PKCS8_KEY, stub.base.clone()));
    let err = auth.installation_for_repo("theplant/nope").unwrap_err();
    assert!(err.contains("404"), "got {err:?}");
    assert!(err.contains("Not Found"), "got {err:?}");
    // The credential is never echoed back in an error.
    assert!(!err.contains("Bearer"), "got {err:?}");
}

/// Against real GitHub. Ignored unless the App's credentials are present.
#[test]
#[ignore = "needs HQ_GITHUB_APP_ID and an App private key"]
fn real_github_accepts_our_app_jwt() {
    let auth = AppAuth::from_env().expect("App credentials in the environment");
    let app = auth.app_identity().expect("GitHub accepts the App JWT");
    assert!(app.id > 0);
    let installs = auth.installations().expect("list installations");
    println!("app {} ({}) installations={}", app.name, app.id, installs.len());
}
