use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

pub const TEST_URL: &str = "host=/tmp dbname=hq_test";

static SEQ: AtomicU64 = AtomicU64::new(1);

pub struct Ctx {
    pub schema: String,
}

impl Ctx {
    pub fn new() -> Self {
        let schema = format!(
            "s{}_{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let mut c = postgres::Client::connect(TEST_URL, postgres::NoTls)
            .expect("connect hq_test — is PostgreSQL 18 running on /tmp:5432?");
        c.batch_execute(&format!("CREATE SCHEMA {schema}"))
            .expect("create test schema");
        Self { schema }
    }
}

impl Drop for Ctx {
    fn drop(&mut self) {
        if let Ok(mut c) = postgres::Client::connect(TEST_URL, postgres::NoTls) {
            let _ = c.batch_execute(&format!("DROP SCHEMA IF EXISTS {} CASCADE", self.schema));
        }
    }
}

pub fn hq(ctx: &Ctx, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hq"))
        .arg("--database-url")
        .arg(TEST_URL)
        .arg("--schema")
        .arg(&ctx.schema)
        .args(args)
        .output()
        .expect("run hq")
}

pub fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

pub fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).trim().to_string()
}

pub fn hq_ok(ctx: &Ctx, args: &[&str]) -> String {
    let out = hq(ctx, args);
    assert!(
        out.status.success(),
        "hq {args:?} failed: {} {}",
        stdout(&out),
        stderr(&out)
    );
    stdout(&out)
}

#[allow(dead_code)]
pub fn binary_on_path(name: &str) -> bool {
    Command::new(name).arg("--version").output().is_ok()
}

pub mod ghstub;
pub mod gitorigin;
