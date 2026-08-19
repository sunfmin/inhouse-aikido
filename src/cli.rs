use crate::domain::{FindingKind, Fingerprint, Observation, TargetKind};
use crate::github::app::AppAuth;
use crate::service::Hq;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "hq", about = "In-house Aikido HQ CLI")]
pub struct Cli {
    /// Postgres connection string. Default: local socket, database hq.
    #[arg(long, env = "HQ_DATABASE_URL", default_value = "host=/tmp dbname=hq")]
    pub database_url: String,
    /// Postgres schema (isolated per test; production uses hq).
    #[arg(long, env = "HQ_SCHEMA", default_value = "hq")]
    pub schema: String,
    /// Where the Gate, annotations, and Remediations go: `real` GitHub, or the
    /// `fake` backend used by tests and local development.
    #[arg(long, env = "HQ_GITHUB_BACKEND", default_value = "fake")]
    pub github_backend: String,
    /// Where exploitability intel comes from: `real` (FIRST's EPSS and CISA's
    /// KEV) or `fake`, which only reads what is already cached and makes no
    /// outbound call.
    #[arg(long, env = "HQ_INTEL_BACKEND", default_value = "fake")]
    pub intel_backend: String,
    /// Whether HQ asks a leaked credential's provider if it still works:
    /// `off` (the default) or `real`. Verification sends the credential to its
    /// own provider and nowhere else, and is an Operator's decision to make.
    #[arg(long, env = "HQ_VERIFY_SECRETS", default_value = "off")]
    pub verify_secrets: String,
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    Enroll {
        kind: String,
        name: String,
        #[arg(long)]
        revision: String,
    },
    Unenroll {
        name: String,
    },
    Targets,
    FakeObs {
        name: String,
        revision: String,
        #[arg(long)]
        engine: String,
        #[arg(long)]
        problem: String,
        #[arg(long)]
        location: String,
        #[arg(long, default_value = "sca")]
        kind: String,
        #[arg(long)]
        fixed: Option<String>,
        #[arg(long)]
        package: Option<String>,
        #[arg(long)]
        manifest: Option<String>,
        #[arg(long, default_value = "")]
        message: String,
        /// Line the Engine saw it on, for the PR annotation.
        #[arg(long)]
        line: Option<u32>,
        /// runtime, development, or unknown (the default)
        #[arg(long, default_value = "unknown")]
        scope: String,
        /// critical, high, medium, low, or unknown (the default)
        #[arg(long, default_value = "unknown")]
        severity: String,
    },
    FakeFail {
        name: String,
        revision: String,
    },
    /// Seed the intel cache, for tests and for an HQ with no outbound access.
    FakeIntel {
        cve: String,
        #[arg(long)]
        epss: Option<f64>,
        #[arg(long)]
        percentile: Option<f64>,
        #[arg(long, default_value_t = false)]
        known_exploited: bool,
    },
    Scan {
        name: String,
        #[arg(long)]
        revision: Option<String>,
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Comma-separated Engine names: fake,gitleaks,trivy,opengrep
        #[arg(long, default_value = "fake")]
        r#use: String,
    },
    Findings {
        #[arg(long)]
        target: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        state: Option<String>,
        #[arg(long)]
        kind: Option<String>,
        /// runtime, development, or unknown
        #[arg(long)]
        scope: Option<String>,
        /// Hide anything less bad than this: critical, high, medium, low
        #[arg(long)]
        min_severity: Option<String>,
        /// Only CVEs CISA says are already being exploited
        #[arg(long, default_value_t = false)]
        known_exploited: bool,
        /// Secrets only: active, inactive, or unverified
        #[arg(long)]
        validity: Option<String>,
    },
    /// Change what a Target's Gate blocks on.
    Policy {
        name: String,
        /// Fail the Gate on new development-scope Findings too. Off by default.
        #[arg(long)]
        gate_dev_scope: Option<bool>,
    },
    /// One Finding as JSON.
    Show {
        fingerprint: String,
    },
    /// Agent Brief for one Finding, or the next agent-fixable Open Finding.
    Brief {
        fingerprint: Option<String>,
    },
    Dismissed,
    Reopen {
        fingerprint: String,
    },
    Dismiss {
        fingerprint: String,
    },
    HandlePr {
        #[arg(long)]
        repo: String,
        #[arg(long)]
        number: u64,
        #[arg(long)]
        head: String,
        #[arg(long)]
        base: String,
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long, default_value = "fake")]
        r#use: String,
    },
    HandleComment {
        #[arg(long)]
        repo: String,
        #[arg(long)]
        number: u64,
        #[arg(long)]
        author: String,
        #[arg(long, default_value_t = false)]
        can_write: bool,
        #[arg(long)]
        body: String,
    },
    IntelRescan {
        /// Comma-separated Engine names (default fake; pass trivy,gitleaks,opengrep to use them)
        #[arg(long, default_value = "fake")]
        r#use: String,
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Scan every Target here and now instead of queueing the Scans.
        #[arg(long, default_value_t = false)]
        now: bool,
    },
    GithubDump,
    /// What the Scan queue is doing: what is waiting, running, and how long it took.
    Scans {
        #[arg(long, default_value_t = 20)]
        limit: i64,
    },
    /// Run queued Scans.
    Work {
        /// How many Scans to run at once.
        #[arg(long, env = "HQ_WORKERS", default_value_t = 2)]
        workers: usize,
        /// Stop once the queue is empty instead of waiting for more work.
        #[arg(long, default_value_t = false)]
        drain: bool,
        /// How long a claimed Scan may go silent before another worker takes it.
        #[arg(long, default_value_t = 900)]
        lease_secs: u64,
    },
    /// Receive GitHub App webhooks and act on them.
    Serve {
        /// Address to listen on.
        #[arg(long, env = "HQ_LISTEN", default_value = "127.0.0.1:8787")]
        addr: String,
        /// Comma-separated Engine names to run when a PR arrives.
        #[arg(long, default_value = "fake")]
        r#use: String,
        /// Scan workers to run alongside the listener. 0 leaves the queue to a
        /// separate `hq work`.
        #[arg(long, env = "HQ_WORKERS", default_value_t = 2)]
        workers: usize,
    },
    /// App identity and installation diagnostics. Needs no database.
    Github {
        #[command(subcommand)]
        sub: GithubCmd,
    },
}

#[derive(Subcommand, Debug)]
pub enum GithubCmd {
    /// Print the App HQ authenticates as.
    Whoami,
    /// List the App's installations and the repositories each one covers.
    Installations,
}

pub fn run<I, T>(args: I) -> Result<String, String>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = Cli::try_parse_from(args).map_err(|e| e.to_string())?;
    // Diagnostics answer "is the App wired up", which is true or false before
    // HQ has any Target, so they do not open the Store.
    if let Cmd::Github { sub } = &cli.cmd {
        return github_cmd(sub);
    }
    // The server opens HQ once per delivery, not once for the process.
    if let Cmd::Serve {
        addr,
        r#use,
        workers,
    } = &cli.cmd
    {
        return serve_cmd(&cli, addr, r#use, *workers);
    }
    // Neither touches HQ's state, and both can run while workers are writing —
    // so neither may save, or it would write back a snapshot taken before the
    // worker's. Opening the Store once still creates the schema.
    if let Cmd::Scans { limit } = &cli.cmd {
        let hq = open_hq(&cli)?;
        return scans_cmd(&hq, *limit);
    }
    if let Cmd::Work {
        workers,
        drain,
        lease_secs,
    } = &cli.cmd
    {
        drop(open_hq(&cli)?);
        return work_cmd(&cli, *workers, *drain, *lease_secs);
    }
    let mut hq = open_hq(&cli)?;
    let out = dispatch(&mut hq, cli.cmd)?;
    hq.save()?;
    Ok(out)
}

fn open_hq(cli: &Cli) -> Result<Hq, String> {
    Ok(open_hq_for(
        &cli.database_url,
        &cli.schema,
        &cli.github_backend,
        &cli.intel_backend,
    )?
    .with_verifier(secret_verifier(&cli.verify_secrets)?))
}

/// Open HQ on the named backend. Shared with `hq serve`, which opens one per
/// delivery.
pub fn open_hq_for(
    database_url: &str,
    schema: &str,
    backend: &str,
    intel_backend: &str,
) -> Result<Hq, String> {
    let hq = open_on_github(database_url, schema, backend)?;
    Ok(hq.with_intel(intel_source(intel_backend)?))
}

/// `off` is the default and makes no call: HQ does not hand a Target's
/// credentials to a third party unless an Operator asks it to.
fn secret_verifier(backend: &str) -> Result<Box<dyn crate::verify::SecretVerifier>, String> {
    match backend {
        "off" | "none" | "fake" => Ok(Box::new(crate::verify::NoVerification)),
        "real" | "providers" => Ok(Box::new(crate::verify::ProviderVerifier::new())),
        other => Err(format!(
            "unknown --verify-secrets {other}: expected `off` or `real`"
        )),
    }
}

/// `fake` reads the intel cache and nothing else — no outbound call HQ was not
/// asked to make, which is also what keeps tests off the network.
fn intel_source(backend: &str) -> Result<Box<dyn crate::intel::IntelSource>, String> {
    match backend {
        "fake" | "none" => Ok(Box::new(crate::intel::NoIntel)),
        "real" | "public" => Ok(Box::new(crate::intel::PublicIntel::new())),
        other => Err(format!(
            "unknown --intel-backend {other}: expected `fake` or `real`"
        )),
    }
}

fn open_on_github(database_url: &str, schema: &str, backend: &str) -> Result<Hq, String> {
    match backend {
        "fake" => Hq::open(database_url, schema),
        "real" | "github" => {
            // One AppAuth, shared: the Gate and the clone use the same
            // installation token cache.
            let auth = std::sync::Arc::new(std::sync::Mutex::new(
                crate::github::app::AppAuth::from_env()?,
            ));
            let hq = Hq::open_with_github(
                database_url,
                schema,
                Box::new(crate::github::real::RealGithub::new(auth.clone())),
            )?;
            Ok(hq
                .with_checkout(Box::new(crate::workspace::GitCheckout::new(Box::new(
                    auth.clone(),
                ))))
                .with_remediator(Box::new(crate::remediation::GitRemediator::new(Box::new(
                    crate::workspace::GitCheckout::new(Box::new(auth)),
                )))))
        }
        other => Err(format!(
            "unknown --github-backend {other}: expected `fake` or `real`"
        )),
    }
}

fn serve_cmd(cli: &Cli, addr: &str, uses: &str, workers: usize) -> Result<String, String> {
    let config = crate::webhook::ServeConfig {
        secret: std::env::var("HQ_WEBHOOK_SECRET").unwrap_or_default(),
        database_url: cli.database_url.clone(),
        schema: cli.schema.clone(),
        github_backend: cli.github_backend.clone(),
        intel_backend: cli.intel_backend.clone(),
        engines: uses.split(',').map(|s| s.trim().to_string()).collect(),
    };
    let server = crate::webhook::WebhookServer::bind(addr, config)?;
    println!("hq serve: listening on {}", server.local_addr());
    // Deliveries only enqueue Scans, so unless somebody else runs `hq work` the
    // queue would just grow. Run the workers here by default.
    if workers > 0 {
        let worker_config = worker_config(cli, workers, 900);
        std::thread::spawn(move || {
            crate::worker::run_pool(worker_config, false, None);
        });
        println!("hq serve: {workers} scan workers");
    }
    server.run(None);
    Ok("hq serve: stopped".into())
}

fn worker_config(cli: &Cli, workers: usize, lease_secs: u64) -> crate::worker::WorkerConfig {
    crate::worker::WorkerConfig {
        database_url: cli.database_url.clone(),
        schema: cli.schema.clone(),
        github_backend: cli.github_backend.clone(),
        intel_backend: cli.intel_backend.clone(),
        workers,
        lease: std::time::Duration::from_secs(lease_secs),
        poll: std::time::Duration::from_millis(500),
    }
}

fn work_cmd(cli: &Cli, workers: usize, drain: bool, lease_secs: u64) -> Result<String, String> {
    // Workers open HQ per job, under the write lock, so this command does not
    // hold one open for its whole life.
    let done = crate::worker::run_pool(worker_config(cli, workers, lease_secs), drain, None);
    Ok(format!("ran {done} scans"))
}

fn scans_cmd(hq: &Hq, limit: i64) -> Result<String, String> {
    let rows = hq.store.queue().list(limit)?;
    if rows.is_empty() {
        return Ok("no scans".into());
    }
    let mut out = Vec::new();
    for row in rows {
        let mut line = format!(
            "{} {} {}@{} engines={} state={}",
            row.id,
            row.purpose.as_str(),
            row.target,
            short(&row.revision),
            row.engines.join(","),
            row.state
        );
        if let Some(worker) = row.claimed_by {
            line.push_str(&format!(" worker={worker}"));
        }
        if let Some(waited) = row.waited_secs {
            line.push_str(&format!(" waited={waited:.1}s"));
        }
        if let Some(took) = row.took_secs {
            line.push_str(&format!(" took={took:.1}s"));
        }
        if let Some(note) = row.note.filter(|n| !n.is_empty()) {
            line.push_str(&format!(" note={note:?}"));
        }
        out.push(line);
    }
    Ok(out.join("\n"))
}

fn short(revision: &str) -> String {
    if revision.len() > 12 && revision.chars().all(|c| c.is_ascii_hexdigit()) {
        revision[..12].to_string()
    } else {
        revision.to_string()
    }
}

fn github_cmd(sub: &GithubCmd) -> Result<String, String> {
    let mut auth = AppAuth::from_env()?;
    match sub {
        GithubCmd::Whoami => {
            let app = auth.app_identity()?;
            let slug = app.slug.as_deref().unwrap_or("-");
            let owner = app.owner.as_ref().map(|o| o.login.as_str()).unwrap_or("-");
            Ok(format!(
                "app id={} slug={} owner={} name={:?}",
                app.id, slug, owner, app.name
            ))
        }
        GithubCmd::Installations => {
            let installs = auth.installations()?;
            if installs.is_empty() {
                return Ok("no installations".into());
            }
            let mut out = Vec::new();
            for install in installs {
                let account = install
                    .account
                    .as_ref()
                    .map(|a| a.login.as_str())
                    .unwrap_or("-");
                let selection = install.repository_selection.as_deref().unwrap_or("-");
                match auth.installation_repos(install.id) {
                    Ok(repos) => {
                        out.push(format!(
                            "installation id={} account={} selection={} repos={}",
                            install.id,
                            account,
                            selection,
                            repos.len()
                        ));
                        for repo in repos {
                            out.push(format!("  {repo}"));
                        }
                    }
                    Err(e) => out.push(format!(
                        "installation id={} account={} selection={} repos=? ({e})",
                        install.id, account, selection
                    )),
                }
            }
            Ok(out.join("\n"))
        }
    }
}

fn parse_kind(s: &str) -> Result<FindingKind, String> {
    match s {
        "sca" => Ok(FindingKind::Sca),
        "secret" => Ok(FindingKind::Secret),
        "sast" => Ok(FindingKind::Sast),
        "iac" => Ok(FindingKind::Iac),
        "license" => Ok(FindingKind::License),
        other => Err(format!("unknown kind {other}")),
    }
}

fn parse_target_kind(s: &str) -> Result<TargetKind, String> {
    match s {
        "github" => Ok(TargetKind::Github),
        "image" => Ok(TargetKind::Image),
        other => Err(format!("unknown target kind {other}")),
    }
}

fn dispatch(hq: &mut Hq, cmd: Cmd) -> Result<String, String> {
    match cmd {
        Cmd::Enroll {
            kind,
            name,
            revision,
        } => hq.enroll(parse_target_kind(&kind)?, &name, &revision),
        Cmd::Unenroll { name } => hq.unenroll(&name),
        Cmd::Targets => Ok(hq.list_targets()),
        Cmd::FakeObs {
            name,
            revision,
            engine,
            problem,
            location,
            kind,
            fixed,
            package,
            manifest,
            message,
            line,
            scope,
            severity,
        } => {
            let scope = crate::domain::Scope::parse(&scope)
                .ok_or_else(|| format!("unknown --scope {scope}"))?;
            let severity = crate::domain::Severity::parse(&severity)
                .ok_or_else(|| format!("unknown --severity {severity}"))?;
            hq.add_fake_obs(
                &name,
                &revision,
                Observation {
                    engine,
                    problem_id: problem,
                    location_key: location,
                    kind: parse_kind(&kind)?,
                    package,
                    manifest,
                    fixed_version: fixed,
                    message,
                    line,
                    scope,
                    severity,
                    secret: None,
                },
            );
            Ok("ok".into())
        }
        Cmd::FakeFail { name, revision } => {
            hq.add_fake_fail(&name, &revision);
            Ok("ok".into())
        }
        Cmd::FakeIntel {
            cve,
            epss,
            percentile,
            known_exploited,
        } => {
            let mut one = std::collections::HashMap::new();
            one.insert(
                cve.clone(),
                crate::intel::CveIntel {
                    epss,
                    percentile,
                    known_exploited,
                },
            );
            hq.store.cache_intel(&one)?;
            Ok(format!("cached {cve}"))
        }
        Cmd::Scan {
            name,
            revision,
            workspace,
            r#use,
        } => {
            let names: Vec<&str> = r#use.split(',').map(str::trim).collect();
            hq.scan_named(
                &name,
                revision.as_deref(),
                &names,
                workspace.as_deref(),
                false,
            )
        }
        Cmd::Findings {
            target,
            json,
            state,
            kind,
            scope,
            min_severity,
            known_exploited,
            validity,
        } => {
            if let Some(s) = scope.as_deref() {
                crate::domain::Scope::parse(s)
                    .ok_or_else(|| format!("unknown --scope {s}: runtime, development, unknown"))?;
            }
            let min_severity = min_severity
                .as_deref()
                .map(|s| {
                    crate::domain::Severity::parse(s)
                        .ok_or_else(|| format!("unknown --min-severity {s}"))
                })
                .transpose()?;
            let validity = validity
                .as_deref()
                .map(|v| {
                    crate::domain::Validity::parse(v)
                        .ok_or_else(|| format!("unknown --validity {v}"))
                })
                .transpose()?;
            let filter = crate::service::FindingFilter {
                target: target.as_deref(),
                state: state.as_deref(),
                kind: kind.as_deref(),
                scope: scope.as_deref(),
                min_severity,
                known_exploited,
                validity,
            };
            if json {
                hq.findings_json(&filter)
            } else {
                Ok(hq.findings_text(&filter))
            }
        }
        Cmd::Policy {
            name,
            gate_dev_scope,
        } => hq.set_policy(&name, gate_dev_scope),
        Cmd::Show { fingerprint } => {
            let fp = Fingerprint::parse(&fingerprint).ok_or("bad fingerprint")?;
            hq.show(&fp)
        }
        Cmd::Brief { fingerprint } => {
            let parsed = fingerprint
                .as_deref()
                .map(|s| Fingerprint::parse(s).ok_or("bad fingerprint"))
                .transpose()?;
            hq.brief(parsed.as_ref())
        }
        Cmd::Dismissed => Ok(hq.dismissed_text()),
        Cmd::Reopen { fingerprint } => {
            let fp = Fingerprint::parse(&fingerprint).ok_or("bad fingerprint")?;
            hq.reopen(&fp)
        }
        Cmd::Dismiss { fingerprint } => {
            let fp = Fingerprint::parse(&fingerprint).ok_or("bad fingerprint")?;
            hq.dismiss(&fp)
        }
        Cmd::HandlePr {
            repo,
            number,
            head,
            base,
            workspace,
            r#use,
        } => {
            let names: Vec<&str> = r#use.split(',').map(str::trim).collect();
            hq.handle_pr_named(&repo, number, &head, &base, &names, workspace.as_deref())
        }
        Cmd::HandleComment {
            repo,
            number,
            author,
            can_write,
            body,
        } => hq.handle_comment(&repo, number, &author, can_write, &body),
        Cmd::IntelRescan {
            r#use,
            workspace,
            now,
        } => {
            let names: Vec<&str> = r#use.split(',').map(str::trim).collect();
            if now {
                hq.intel_rescan_named(&names, workspace.as_deref())
            } else {
                hq.queue_rescan(&names)
            }
        }
        Cmd::GithubDump => Ok(hq.github_dump()),
        // Handled before HQ is opened, because neither may save.
        Cmd::Scans { .. } => Err("hq scans is handled earlier".into()),
        Cmd::Work { .. } => Err("hq work is handled earlier".into()),
        // Both are handled before the Store is opened.
        Cmd::Github { sub } => github_cmd(&sub),
        Cmd::Serve { .. } => Err("hq serve is handled before HQ is opened".into()),
    }
}
