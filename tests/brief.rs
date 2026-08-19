mod common;
use common::hq_ok;

#[test]
fn findings_json_and_brief_pick_secret_first() {
    let ctx = common::Ctx::new();
    hq_ok(
        &ctx,
        &["enroll", "github", "acme/api", "--revision", "main"],
    );
    hq_ok(
        &ctx,
        &[
            "fake-obs",
            "acme/api",
            "main",
            "--engine",
            "trivy",
            "--problem",
            "MIT",
            "--location",
            "go.mod::htmlgo",
            "--kind",
            "license",
            "--package",
            "htmlgo",
            "--manifest",
            "go.mod",
        ],
    );
    hq_ok(
        &ctx,
        &[
            "fake-obs",
            "acme/api",
            "main",
            "--engine",
            "trivy",
            "--problem",
            "CVE-1",
            "--location",
            "pnpm-lock.yaml::hono",
            "--kind",
            "sca",
            "--package",
            "hono",
            "--manifest",
            "pnpm-lock.yaml",
            "--fixed",
            "4.0.0",
        ],
    );
    hq_ok(
        &ctx,
        &[
            "fake-obs",
            "acme/api",
            "main",
            "--engine",
            "gitleaks",
            "--problem",
            "github-pat",
            "--location",
            "src/app.ts",
            "--kind",
            "secret",
        ],
    );
    hq_ok(&ctx, &["scan", "acme/api"]);

    let json = hq_ok(&ctx, &["findings", "--json", "--state", "open"]);
    assert!(json.contains("\"agent_fixable\": true"));
    assert!(json.contains("github-pat"));

    let brief = hq_ok(&ctx, &["brief"]);
    assert!(brief.contains("## Agent Brief"));
    assert!(brief.contains("github-pat"));
    assert!(brief.contains("Do not `hq dismiss`"));
    assert!(!brief.contains("CVE-1") || brief.contains("github-pat"));

    let sca = hq_ok(&ctx, &["brief", "acme/api|CVE-1|pnpm-lock.yaml::hono"]);
    assert!(sca.contains("Pin hono to 4.0.0"));
    assert!(sca.contains("4.0.0"));

    let shown = hq_ok(&ctx, &["show", "acme/api|github-pat|src/app.ts"]);
    assert!(shown.contains("\"kind\": \"secret\""));
}
