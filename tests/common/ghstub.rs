#![allow(dead_code)]

//! A stand-in for the GitHub API, on localhost.
//!
//! It speaks the routes HQ actually uses — App auth, installation tokens, and
//! Check Runs — and records every request so a test can assert what HQ sent.
//! Nothing here reaches the network.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

/// The repositories the stubbed App is installed on.
const KNOWN_REPOS: [&str; 2] = ["acme/web", "acme/worker"];

#[derive(Debug, Clone)]
pub struct Call {
    pub method: String,
    pub path: String,
    pub authorization: String,
    pub body: serde_json::Value,
}

#[derive(Clone, Copy, Default)]
pub struct StubOptions {
    /// Hand back a token that is already stale, to prove HQ renews it.
    pub stale_first_token: bool,
    /// Refuse every Check Run write, to prove the Gate does not pass silently.
    pub reject_check_writes: bool,
}

pub struct GithubStub {
    pub base: String,
    calls: Arc<Mutex<Vec<Call>>>,
}

impl GithubStub {
    pub fn start() -> Self {
        Self::with(StubOptions::default())
    }

    pub fn with(options: StubOptions) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let base = format!("http://{}", listener.local_addr().unwrap());
        let calls = Arc::new(Mutex::new(Vec::new()));
        let log = calls.clone();

        std::thread::spawn(move || {
            let mut token_calls = 0usize;
            let mut next_check_id = 100u64;
            let mut checks: HashMap<String, u64> = HashMap::new();

            for stream in listener.incoming() {
                let Ok(mut sock) = stream else { continue };
                let mut reader = BufReader::new(sock.try_clone().unwrap());
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).is_err() {
                    continue;
                }
                let mut parts = request_line.split_whitespace();
                let method = parts.next().unwrap_or("GET").to_string();
                let path = parts.next().unwrap_or("/").to_string();

                let mut authorization = String::new();
                let mut length = 0usize;
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
                        authorization = header[header.len() - v.len()..].trim().to_string();
                    }
                    if let Some(v) = lower.strip_prefix("content-length:") {
                        length = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut raw = vec![0u8; length];
                if length > 0 {
                    let _ = reader.read_exact(&mut raw);
                }
                let body: serde_json::Value =
                    serde_json::from_slice(&raw).unwrap_or(serde_json::Value::Null);

                log.lock().unwrap().push(Call {
                    method: method.clone(),
                    path: path.clone(),
                    authorization,
                    body: body.clone(),
                });

                let route = path.split('?').next().unwrap_or(&path).to_string();
                let (status, payload) = if route == "/app" {
                    (200, app_json())
                } else if route == "/app/installations" {
                    (200, installations_json())
                } else if route.starts_with("/app/installations/") && route.ends_with("/access_tokens")
                {
                    let expiry = if options.stale_first_token && token_calls == 0 {
                        "2000-01-01T00:00:00Z"
                    } else {
                        "2099-01-01T00:00:00Z"
                    };
                    let n = token_calls;
                    token_calls += 1;
                    (
                        201,
                        format!(r#"{{"token":"ghs_installation_{n}","expires_at":"{expiry}"}}"#),
                    )
                } else if route == "/installation/repositories" {
                    (200, repositories_json())
                } else if route.ends_with("/installation") && route.starts_with("/repos/") {
                    // GitHub 404s for a repo the App is not installed on.
                    if KNOWN_REPOS.iter().any(|r| route == format!("/repos/{r}/installation")) {
                        (200, installation_json())
                    } else {
                        (404, r#"{"message":"Not Found"}"#.to_string())
                    }
                } else if route.contains("/check-runs") && method == "GET" {
                    let sha = route
                        .split("/commits/")
                        .nth(1)
                        .and_then(|r| r.split('/').next())
                        .unwrap_or("");
                    match checks.get(sha) {
                        Some(id) => (200, format!(r#"{{"total_count":1,"check_runs":[{{"id":{id}}}]}}"#)),
                        None => (200, r#"{"total_count":0,"check_runs":[]}"#.to_string()),
                    }
                } else if route.ends_with("/check-runs") && method == "POST" {
                    if options.reject_check_writes {
                        (500, r#"{"message":"Server Error"}"#.to_string())
                    } else {
                        let id = next_check_id;
                        next_check_id += 1;
                        if let Some(sha) = body.get("head_sha").and_then(|v| v.as_str()) {
                            checks.insert(sha.to_string(), id);
                        }
                        (201, format!(r#"{{"id":{id},"name":"hq"}}"#))
                    }
                } else if route.contains("/check-runs/") && method == "PATCH" {
                    if options.reject_check_writes {
                        (500, r#"{"message":"Server Error"}"#.to_string())
                    } else {
                        let id: u64 = route.rsplit('/').next().and_then(|s| s.parse().ok()).unwrap_or(0);
                        (200, format!(r#"{{"id":{id},"name":"hq"}}"#))
                    }
                } else {
                    (404, r#"{"message":"Not Found"}"#.to_string())
                };

                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                    payload.len()
                );
                let _ = sock.write_all(response.as_bytes());
                let _ = sock.flush();
                let _ = sock.shutdown(std::net::Shutdown::Write);
            }
        });

        Self { base, calls }
    }

    pub fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    /// Every call whose method matches and whose path contains `needle`.
    pub fn calls_to(&self, method: &str, needle: &str) -> Vec<Call> {
        self.calls()
            .into_iter()
            .filter(|c| c.method == method && c.path.contains(needle))
            .collect()
    }

    pub fn authorization_for(&self, needle: &str) -> String {
        self.calls()
            .into_iter()
            .find(|c| c.path.contains(needle))
            .map(|c| c.authorization)
            .unwrap_or_default()
    }
}

fn app_json() -> String {
    r#"{"id":42,"name":"In-house HQ","slug":"inhouse-hq","owner":{"login":"acme"}}"#.to_string()
}

fn installations_json() -> String {
    r#"[{"id":7,"account":{"login":"acme"},"repository_selection":"selected"}]"#.to_string()
}

fn installation_json() -> String {
    r#"{"id":7,"account":{"login":"acme"},"repository_selection":"selected"}"#.to_string()
}

fn repositories_json() -> String {
    r#"{"total_count":2,"repositories":[{"full_name":"acme/web"},{"full_name":"acme/worker"}]}"#
        .to_string()
}
