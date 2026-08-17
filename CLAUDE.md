# inhouse-aikido

## Agent skills

### Issue tracker

Issues live in this repo's GitHub Issues (`sunfmin/inhouse-aikido`), operated via the `gh` CLI. External PRs are **not** a triage surface. See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary — the five canonical labels (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`) used as-is. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context — one `CONTEXT.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.

### Findings (for agents)

HQ Findings live in Postgres (`HQ_DATABASE_URL`, schema `hq`). An agent that should fix a Finding does **not** open a dashboard.

1. `hq findings --json --state open` — list Open Findings. `agent_fixable: true` means take it.
2. `hq brief` — next agent-fixable Finding as an Agent Brief (secrets first, then SAST, then SCA with a known pin). Or `hq brief '<fingerprint>'`.
3. `hq show '<fingerprint>'` — one Finding as JSON.
4. Implement the brief. Do **not** `hq dismiss`.
5. `hq scan <target> --workspace <clone> --use gitleaks,trivy,opengrep` then `hq show` again — state must no longer be Open.

License Findings are Operator work. Do not auto-accept a license.
