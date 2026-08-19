//! The App's inbound side: GitHub webhooks.
//!
//! A delivery is verified, acknowledged, and only then acted on — a Scan can
//! take minutes and GitHub's delivery timeout is seconds, so HQ answers first
//! and works after. A PR delivery does not scan inline: it puts a Scan on the
//! queue and returns, so a push storm becomes queue depth rather than a pile of
//! deliveries timing out.
//!
//! See ADR 0020 (HQ stays synchronous) and ADR 0019 (HQ is a GitHub App).

use crate::service::Hq;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;

/// Comment authors GitHub says can write the Target.
const CAN_WRITE: [&str; 3] = ["OWNER", "MEMBER", "COLLABORATOR"];

/// What one delivery asks HQ to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A PR opened or pushed to: Gate its head Revision.
    GatePr {
        repo: String,
        number: u64,
        head: String,
        base: String,
    },
    /// A PR comment aimed at HQ.
    Command {
        repo: String,
        number: u64,
        author: String,
        can_write: bool,
        body: String,
    },
    /// The App gained or lost reach over some repositories.
    Reach {
        installation_id: u64,
        added: Vec<String>,
        removed: Vec<String>,
    },
    /// Acknowledged, and nothing for HQ to do.
    Ignored(String),
}

/// Does the delivery carry a signature made with our webhook secret?
///
/// GitHub signs the raw body with HMAC-SHA256. A missing or malformed header is
/// a mismatch, never a pass.
pub fn signature_matches(secret: &str, body: &[u8], header: &str) -> bool {
    let Some(hex_digest) = header.strip_prefix("sha256=") else {
        return false;
    };
    let Ok(expected) = hex::decode(hex_digest) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&expected).is_ok()
}

/// The signature GitHub would send for this body. Used by tests, and by an
/// Operator checking a secret by hand.
pub fn sign(secret: &str, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac takes any key");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

fn repo_of(payload: &Value) -> Option<String> {
    payload
        .get("repository")?
        .get("full_name")?
        .as_str()
        .map(str::to_string)
}

fn full_names(payload: &Value, key: &str) -> Vec<String> {
    payload
        .get(key)
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|r| r.get("full_name").and_then(|n| n.as_str()))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Read one delivery. An event HQ does not act on is `Ignored`, not an error —
/// GitHub sends plenty HQ has no opinion about.
pub fn parse_event(event: &str, payload: &Value) -> Result<Event, String> {
    let action = payload
        .get("action")
        .and_then(|a| a.as_str())
        .unwrap_or_default();
    match event {
        "pull_request" => {
            if !matches!(action, "opened" | "synchronize" | "reopened") {
                return Ok(Event::Ignored(format!("pull_request {action}")));
            }
            let repo = repo_of(payload).ok_or("pull_request without a repository")?;
            let pr = payload
                .get("pull_request")
                .ok_or("pull_request without a pull_request")?;
            let number = payload
                .get("number")
                .and_then(|n| n.as_u64())
                .or_else(|| pr.get("number").and_then(|n| n.as_u64()))
                .ok_or("pull_request without a number")?;
            let head = pr
                .get("head")
                .and_then(|h| h.get("sha"))
                .and_then(|s| s.as_str())
                .ok_or("pull_request without a head Revision")?
                .to_string();
            let base = pr
                .get("base")
                .and_then(|b| b.get("ref"))
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            Ok(Event::GatePr {
                repo,
                number,
                head,
                base,
            })
        }
        "issue_comment" => {
            if action != "created" {
                return Ok(Event::Ignored(format!("issue_comment {action}")));
            }
            let issue = payload
                .get("issue")
                .ok_or("issue_comment without an issue")?;
            if issue.get("pull_request").is_none() {
                return Ok(Event::Ignored("comment on an issue, not a PR".into()));
            }
            let repo = repo_of(payload).ok_or("issue_comment without a repository")?;
            let number = issue
                .get("number")
                .and_then(|n| n.as_u64())
                .ok_or("issue_comment without a number")?;
            let comment = payload
                .get("comment")
                .ok_or("issue_comment without a comment")?;
            let body = comment
                .get("body")
                .and_then(|b| b.as_str())
                .unwrap_or_default()
                .to_string();
            let author = comment
                .get("user")
                .and_then(|u| u.get("login"))
                .and_then(|l| l.as_str())
                .unwrap_or("unknown")
                .to_string();
            let association = comment
                .get("author_association")
                .and_then(|a| a.as_str())
                .unwrap_or_default();
            Ok(Event::Command {
                repo,
                number,
                author,
                can_write: CAN_WRITE.contains(&association),
                body,
            })
        }
        "installation" | "installation_repositories" => {
            let installation_id = payload
                .get("installation")
                .and_then(|i| i.get("id"))
                .and_then(|i| i.as_u64())
                .ok_or("installation event without an installation id")?;
            let (added, removed) = match action {
                "deleted" => (vec![], full_names(payload, "repositories")),
                "removed" => (vec![], full_names(payload, "repositories_removed")),
                _ => {
                    let mut added = full_names(payload, "repositories");
                    added.extend(full_names(payload, "repositories_added"));
                    (added, full_names(payload, "repositories_removed"))
                }
            };
            Ok(Event::Reach {
                installation_id,
                added,
                removed,
            })
        }
        other => Ok(Event::Ignored(other.to_string())),
    }
}

/// Act on one delivery. An event about a Target HQ does not track, or one whose
/// Baseline is not written yet, is a no-op rather than a failure — Enrollment is
/// opt-in and Baseline day fails nothing.
pub fn handle_event(hq: &mut Hq, event: &Event, engines: &[&str]) -> Result<String, String> {
    match event {
        Event::GatePr {
            repo,
            number,
            head,
            base,
        } => {
            if !hq.tracks(repo) {
                return Ok(format!("{repo} is not Enrolled, ignored"));
            }
            if !hq.baseline_ready(repo) {
                return Ok(format!("{repo} has no Baseline yet, ignored"));
            }
            let id = hq.store.queue().enqueue(&crate::queue::JobRequest {
                target: repo.clone(),
                revision: head.clone(),
                engines: engines.iter().map(|e| e.to_string()).collect(),
                purpose: crate::queue::Purpose::Gate,
                pr_number: Some(*number),
                base_revision: Some(base.clone()),
            })?;
            Ok(format!("queued {repo} pr={number} scan={id}"))
        }
        Event::Command {
            repo,
            number,
            author,
            can_write,
            body,
        } => {
            if !body.trim_start().starts_with("/hq ") {
                return Ok("not an HQ command, ignored".into());
            }
            if !hq.tracks(repo) {
                return Ok(format!("{repo} is not Enrolled, ignored"));
            }
            hq.handle_comment(repo, *number, author, *can_write, body)
        }
        Event::Reach {
            installation_id,
            added,
            removed,
        } => {
            for repo in added {
                hq.store.record_installation(repo, *installation_id)?;
            }
            for repo in removed {
                hq.store.forget_installation(repo)?;
            }
            Ok(format!(
                "installation {installation_id}: +{} -{}",
                added.len(),
                removed.len()
            ))
        }
        Event::Ignored(what) => Ok(format!("ignored {what}")),
    }
}

/// How the server reaches HQ for each delivery.
#[derive(Clone)]
pub struct ServeConfig {
    pub secret: String,
    pub database_url: String,
    pub schema: String,
    pub github_backend: String,
    pub engines: Vec<String>,
}

pub struct WebhookServer {
    server: tiny_http::Server,
    config: ServeConfig,
}

impl WebhookServer {
    pub fn bind(addr: &str, config: ServeConfig) -> Result<Self, String> {
        if config.secret.is_empty() {
            return Err(
                "HQ_WEBHOOK_SECRET is not set — HQ will not accept unverified \
                        deliveries"
                    .into(),
            );
        }
        let server =
            tiny_http::Server::http(addr).map_err(|e| format!("cannot listen on {addr}: {e}"))?;
        Ok(Self { server, config })
    }

    pub fn local_addr(&self) -> String {
        self.server
            .server_addr()
            .to_ip()
            .map(|a| a.to_string())
            .unwrap_or_default()
    }

    /// Take one delivery: verify it, acknowledge it, then act on it. Returns
    /// what happened, which is what the server logs and what tests assert on.
    /// `None` means the listener is gone.
    pub fn handle_one(&self) -> Option<Result<String, String>> {
        let mut request = self.server.recv().ok()?;
        let mut body = Vec::new();
        let _ = request.as_reader().read_to_end(&mut body);
        let signature = header(&request, "x-hub-signature-256");
        let event = header(&request, "x-github-event");
        let delivery = header(&request, "x-github-delivery");

        if !signature_matches(&self.config.secret, &body, &signature) {
            respond(request, 401, "signature mismatch");
            return Some(Err(format!(
                "rejected delivery {delivery}: signature mismatch"
            )));
        }
        // Acknowledge before working: a Scan outlives GitHub's delivery timeout.
        respond(request, 202, "accepted");
        Some(self.process(&event, &delivery, &body))
    }

    /// Serve until the listener goes away, or until `limit` deliveries have been
    /// taken. Production passes `None`.
    pub fn run(self, limit: Option<usize>) {
        let mut taken = 0usize;
        while self.handle_one().is_some_and(|outcome| {
            match outcome {
                Ok(msg) => println!("hq serve: {msg}"),
                Err(e) => eprintln!("hq serve: {e}"),
            }
            true
        }) {
            taken += 1;
            if Some(taken) == limit {
                break;
            }
        }
    }

    fn process(&self, event: &str, delivery: &str, body: &[u8]) -> Result<String, String> {
        let mut hq = crate::cli::open_hq_for(
            &self.config.database_url,
            &self.config.schema,
            &self.config.github_backend,
        )?;
        if !delivery.is_empty() && hq.store.delivery_seen(delivery)? {
            return Ok("duplicate delivery, already handled".into());
        }
        let payload: Value =
            serde_json::from_slice(body).map_err(|e| format!("delivery body is not JSON: {e}"))?;
        let parsed = parse_event(event, &payload)?;
        let engines: Vec<&str> = self.config.engines.iter().map(String::as_str).collect();
        let out = handle_event(&mut hq, &parsed, &engines)?;
        hq.save()?;
        if !delivery.is_empty() {
            hq.store.remember_delivery(delivery)?;
        }
        Ok(out)
    }
}

fn header(request: &tiny_http::Request, name: &'static str) -> String {
    request
        .headers()
        .iter()
        .find(|h| h.field.equiv(name))
        .map(|h| h.value.as_str().to_string())
        .unwrap_or_default()
}

fn respond(request: tiny_http::Request, status: u16, message: &str) {
    let response =
        tiny_http::Response::from_string(message).with_status_code(tiny_http::StatusCode(status));
    let _ = request.respond(response);
}
