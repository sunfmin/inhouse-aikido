//! Telling somebody a Finding appeared when no pull request is open.
//!
//! The Gate catches what a Developer is about to merge. It cannot catch the CVE
//! published at 3am against code that has been on `main` for a year — nobody
//! opens a PR for that, so nobody is looking. One digest per Scan, to one Slack
//! channel, is the whole notification surface. It is deliberately not a
//! dashboard.

/// Somewhere a digest can go.
pub trait Notifier: Send + Sync {
    fn name(&self) -> &str;

    /// Is anything configured? With nothing configured HQ behaves exactly as it
    /// did before there was a Notifier.
    fn enabled(&self) -> bool {
        true
    }

    fn post(&self, message: &str) -> Result<(), String>;
}

/// Nowhere. The default.
pub struct Silent;

impl Notifier for Silent {
    fn name(&self) -> &str {
        "none"
    }

    fn enabled(&self) -> bool {
        false
    }

    fn post(&self, _message: &str) -> Result<(), String> {
        Ok(())
    }
}

/// A Slack incoming webhook.
pub struct SlackWebhook {
    url: String,
}

impl SlackWebhook {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }

    /// From `HQ_SLACK_WEBHOOK`, if it is set.
    pub fn from_env() -> Option<Self> {
        std::env::var("HQ_SLACK_WEBHOOK")
            .ok()
            .filter(|u| !u.is_empty())
            .map(Self::new)
    }
}

impl Notifier for SlackWebhook {
    fn name(&self) -> &str {
        "slack"
    }

    fn post(&self, message: &str) -> Result<(), String> {
        let body = serde_json::json!({ "text": message });
        let payload = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
        ureq::post(&self.url)
            .header("Content-Type", "application/json")
            .send(&payload[..])
            .map_err(|e| format!("slack: {e}"))?;
        Ok(())
    }
}
