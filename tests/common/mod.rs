use std::path::Path;
use std::process::{Command, Output};

pub fn hq(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hq"))
        .arg("--data-dir")
        .arg(dir)
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

pub fn hq_ok(dir: &Path, args: &[&str]) -> String {
    let out = hq(dir, args);
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
