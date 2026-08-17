use crate::domain::{FindingKind, Fingerprint, Observation, TargetKind};
use crate::service::Hq;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "hq", about = "In-house Aikido HQ CLI")]
pub struct Cli {
    #[arg(long, env = "HQ_DATA_DIR")]
    pub data_dir: PathBuf,
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
}

pub fn run<I, T>(args: I) -> Result<String, String>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = Cli::try_parse_from(args).map_err(|e| e.to_string())?;
    let mut hq = Hq::open(&cli.data_dir)?;
    let out = dispatch(&mut hq, cli.cmd)?;
    hq.save()?;
    Ok(out)
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
        Cmd::Findings { target } => Ok(hq.findings_text(target.as_deref())),
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
    }
}
