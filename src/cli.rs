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
    },
    FakeFail {
        name: String,
        revision: String,
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
    },
    GithubDump,
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
    let mut hq = open_hq(&cli)?;
    let out = dispatch(&mut hq, cli.cmd)?;
    hq.save()?;
    Ok(out)
}

fn open_hq(cli: &Cli) -> Result<Hq, String> {
    match cli.github_backend.as_str() {
        "fake" => Hq::open(&cli.database_url, &cli.schema),
        "real" | "github" => Hq::open_with_github(
            &cli.database_url,
            &cli.schema,
            Box::new(crate::github::real::RealGithub::from_env()?),
        ),
        other => Err(format!(
            "unknown --github-backend {other}: expected `fake` or `real`"
        )),
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
        } => {
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
                },
            );
            Ok("ok".into())
        }
        Cmd::FakeFail { name, revision } => {
            hq.add_fake_fail(&name, &revision);
            Ok("ok".into())
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
        } => {
            if json {
                hq.findings_json(target.as_deref(), state.as_deref(), kind.as_deref())
            } else {
                Ok(hq.findings_text(target.as_deref(), state.as_deref(), kind.as_deref()))
            }
        }
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
        Cmd::IntelRescan { r#use, workspace } => {
            let names: Vec<&str> = r#use.split(',').map(str::trim).collect();
            hq.intel_rescan_named(&names, workspace.as_deref())
        }
        Cmd::GithubDump => Ok(hq.github_dump()),
        // Handled before the Store is opened.
        Cmd::Github { sub } => github_cmd(&sub),
    }
}
