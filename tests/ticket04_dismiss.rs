mod common;
use common::hq_ok;
use tempfile::tempdir;

#[test]
fn dismiss_on_pr_reopen_from_cli() {
    let dir = tempdir().unwrap();
    let d = dir.path();
    hq_ok(d, &["enroll", "github", "acme/api", "--revision", "main"]);
    hq_ok(d, &["scan", "acme/api"]);

    hq_ok(
        d,
        &[
            "fake-obs",
            "acme/api",
            "pr1",
            "--engine",
            "gitleaks",
            "--problem",
            "aws-key",
            "--location",
            "src/app.rs",
            "--kind",
            "secret",
        ],
    );
    let fail = hq_ok(
        d,
        &[
            "handle-pr",
            "--repo",
            "acme/api",
            "--number",
            "4",
            "--head",
            "pr1",
            "--base",
            "main",
        ],
    );
    assert!(fail.contains("gate=failure"), "{fail}");

    let denied = common::hq(
        d,
        &[
            "handle-comment",
            "--repo",
            "acme/api",
            "--number",
            "4",
            "--author",
            "junior",
            "--body",
            "/hq dismiss acme/api|aws-key|src/app.rs",
        ],
    );
    assert!(!denied.status.success());
    assert!(common::stderr(&denied).contains("cannot write"));

    let dismissed = hq_ok(
        d,
        &[
            "handle-comment",
            "--repo",
            "acme/api",
            "--number",
            "4",
            "--author",
            "dev",
            "--body",
            "/hq dismiss acme/api|aws-key|src/app.rs",
            "--can-write",
        ],
    );
    assert!(dismissed.contains("dismissed"), "{dismissed}");

    let list = hq_ok(d, &["dismissed"]);
    assert!(list.contains("aws-key"));

    // next PR with same secret stays green
    hq_ok(
        d,
        &[
            "fake-obs",
            "acme/api",
            "pr2",
            "--engine",
            "gitleaks",
            "--problem",
            "aws-key",
            "--location",
            "src/app.rs",
            "--kind",
            "secret",
        ],
    );
    let stay = hq_ok(
        d,
        &[
            "handle-pr",
            "--repo",
            "acme/api",
            "--number",
            "5",
            "--head",
            "pr2",
            "--base",
            "main",
        ],
    );
    assert!(stay.contains("gate=success"), "{stay}");

    let reopened = hq_ok(d, &["reopen", "acme/api|aws-key|src/app.rs"]);
    assert!(reopened.contains("reopened"), "{reopened}");

    hq_ok(
        d,
        &[
            "fake-obs",
            "acme/api",
            "pr3",
            "--engine",
            "gitleaks",
            "--problem",
            "aws-key",
            "--location",
            "src/app.rs",
            "--kind",
            "secret",
        ],
    );
    let again = hq_ok(
        d,
        &[
            "handle-pr",
            "--repo",
            "acme/api",
            "--number",
            "6",
            "--head",
            "pr3",
            "--base",
            "main",
        ],
    );
    assert!(again.contains("gate=failure"), "{again}");
}
