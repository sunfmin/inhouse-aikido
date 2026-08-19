# In-house Aikido

Self-hosted application security with swappable engines, no SaaS. An in-house replacement of [Aikido Security](https://aikido.dev), targeting feature parity with all four of its suites. The first release operates **Code**: what developers write and ship — source, dependencies, secrets, IaC, licenses, and container images.

## How it works

Three pieces:

- **HQ** — the long-lived control plane: a Rust CLI (`hq`) backed by PostgreSQL. It holds the inventory of Targets and Findings between scans, and re-scans when engine intel changes.
- **Engines** — swappable scanners (Gitleaks, Trivy, Opengrep) that run as local binaries on your runners. Your source never leaves your infrastructure.
- **App** — the GitHub App identity HQ uses to annotate PRs, fail the Gate, and open Remediation PRs.

The flow: an Operator enrolls a repo or image repo → the first scan writes the Baseline (fails nothing) → from then on, the **Gate** fails a PR only when its Revision has an Open Finding whose Fingerprint is not on the Baseline. For every SCA Finding with a known fixed version, HQ opens a **Remediation** — a one-line dependency pin as a pull request.

## Concepts

| Term | Meaning |
|---|---|
| **Target** | A durable asset HQ tracks — a GitHub repo or an image repo. Exists only after Enrollment. |
| **Revision** | The exact snapshot a Scan ran against — a git commit or an image digest. |
| **Scan** | One Engine run against one Target at one Revision. |
| **Observation** | One Engine's report supporting a Finding. |
| **Finding** | One problem on one kind of Target, deduplicated by Fingerprint. Two Engines hitting the same lockfile CVE are one Finding. |
| **Fingerprint** | A Finding's identity: Target + problem id (CVE or rule) + location key (a file path). Not the line number, not the Engine. |
| **Baseline** | The Fingerprints already Open or Dismissed on the Target's default Revision. |
| **Gate** | The CI verdict on a PR: fails only for Open Findings not on the Baseline. |
| **Remediation** | One atomic safe edit (a dependency pin) that HQ opens as a PR, linked to every Finding it would fix. |
| **Dismiss / Reopen** | A Developer's or Operator's decision to stop nagging a Fingerprint — until an Operator reopens it. |

Finding states: **Open** (latest Scan still produces the Observation, not Dismissed) · **Fixed** (later Scan no longer produces it) · **Dismissed**.

## Engines

| Engine | License | What it finds |
|---|---|---|
| [Gitleaks](https://github.com/gitleaks/gitleaks) | MIT | Secrets |
| [Trivy](https://github.com/aquasecurity/trivy) | Apache-2.0 | SCA (known-vulnerable dependencies), licenses, IaC, container images |
| [Opengrep](https://github.com/opengrep/opengrep) | LGPL-2.1 | SAST |
| `fake` | built in | Deterministic synthetic Observations — for tests and demos |

Engine choices are recorded in ADRs: [0002](docs/adr/0002-in-house-swappable-engines.md), [0016](docs/adr/0016-v1-engines.md), [0017](docs/adr/0017-opengrep-not-semgrep.md).

## Quick start

Requirements: Rust (stable), PostgreSQL, and any Engine binaries you want to use (`gitleaks`, `trivy`, `opengrep` on `PATH`).

```sh
# 1. A Postgres server. HQ creates its schema automatically (CREATE TABLE IF NOT EXISTS).
createdb hq

# 2. Build the CLI
cargo build --release

# 3. Enroll a repo. The first scan writes the Baseline; the Gate starts after that.
hq enroll github sunfmin/whats-hot --revision main

# 4. Scan it with real engines. HQ clones the Revision itself; pass
#    --workspace only to point it at a checkout you already have.
hq scan sunfmin/whats-hot --use gitleaks,trivy,opengrep

# 5. See the Findings
hq findings
```

The database connection defaults to the local socket, database `hq`; override with `HQ_DATABASE_URL` and isolate schemas with `HQ_SCHEMA`.

## CLI

```
hq [OPTIONS] <COMMAND>

  enroll        Make a repo or image repo a Target
  unenroll      Stop tracking a Target
  targets       List Targets
  scan          Run Engines against a Target
  findings      List Findings (text or --json, filter by --target/--state/--kind)
  show          One Finding as JSON
  brief         Agent Brief for one Finding, or the next agent-fixable Open Finding
  dismissed     List Dismissed Findings
  dismiss       Dismiss a Finding by Fingerprint
  reopen        Reopen a Dismissed Finding
  handle-pr     Scan a PR Revision and set the Gate check
  handle-comment  Handle dismiss/reopen commands from PR comments
  intel-rescan  Queue a re-Scan of every Target when Engine intel changes
  scans         What the Scan queue is doing: queued, running, done, failed
  work          Run queued Scans
  fake-obs / fake-fail  Inject synthetic Observations for tests and demos
  github        App identity diagnostics: whoami, installations
  github-dump   Dump pending App actions (checks, PRs)
```

Every command takes `--github-backend`: `fake` (the default — an in-process GitHub for tests and local development, inspected with `hq github-dump`) or `real`, which writes to GitHub as the App. Run `hq <command> --help` for details.

```sh
hq --github-backend real handle-pr acme/web --number 42 --head <sha> --base main --use trivy,gitleaks,opengrep
```

Against the real backend the Gate is a Check Run named `hq` on the PR's head Revision: one per Revision, updated rather than restacked on the next Scan. Every Open Finding on that Revision is annotated in the file it is in — `failure` for what is new, `warning` for Baseline debt — and each annotation carries the Fingerprint and the `/hq dismiss` command for it. Engines that fail write a failed Check Run, and a Check Run HQ cannot write is an error, never a silent pass.

### The GitHub App

HQ authenticates as a GitHub App, never as a person. Point it at the App's credentials and check the wiring — `hq github` needs no database:

```sh
export HQ_GITHUB_APP_ID=123456
export HQ_GITHUB_PRIVATE_KEY_PATH=/path/to/app.private-key.pem   # or HQ_GITHUB_PRIVATE_KEY inline
export HQ_GITHUB_API_BASE=https://api.github.com                 # override for GitHub Enterprise

hq github whoami          # the App HQ authenticates as
hq github installations   # installations and the repos each one covers
```

HQ mints a short-lived RS256 JWT from the private key, exchanges it for an installation access token, and reuses that token until it nears the expiry GitHub reports. See [ADR 0020](docs/adr/0020-synchronous-http-stack.md) for why the HTTP stack is synchronous.

### Webhooks

`hq serve` is the App's inbound side. Point the App's webhook URL at it:

```sh
export HQ_WEBHOOK_SECRET=...      # the App's webhook secret; HQ refuses to serve without it
hq --github-backend real serve --addr 0.0.0.0:8787 --use trivy,gitleaks,opengrep
```

Every delivery's HMAC signature is verified before anything happens; an unverified delivery is rejected with 401 and leaves no trace. A verified one is acknowledged with 202 *before* the Scan runs, because a Scan outlives GitHub's delivery timeout. Then:

| Event | What HQ does |
|---|---|
| `pull_request` opened / synchronize / reopened | Queue a Scan of the head Revision; the worker writes the Check Run |
| `issue_comment` starting `/hq ` | Run the command — `/hq dismiss <fingerprint>` from someone who can write the Target |
| `installation`, `installation_repositories` | Record which repos the App can reach |
| anything else | Acknowledged and ignored |

A delivery id HQ has already handled is not handled again. An event about a repo that is not Enrolled, or a Target whose Baseline is not written yet, is a no-op — Enrollment is opt-in and Baseline day fails nothing.

### The Scan queue

A delivery does not scan; it queues a Scan and returns. Workers claim queued Scans and run them, so a push storm across ten repos is queue depth rather than a pile of deliveries timing out, and a hung Engine on one Target does not stop the others.

```sh
hq scans                              # queued, running, done, failed, discarded — with timing
hq work --workers 4                   # a worker process; --drain to stop once the queue is empty
hq intel-rescan --use trivy,gitleaks  # queues one Scan per Target
```

`hq serve` runs a pool itself (`--workers`, default 2), so a single-process deployment needs nothing else. Claiming uses `FOR UPDATE SKIP LOCKED`, so two workers never take the same Scan, and a job whose worker dies stops heartbeating and becomes claimable again instead of staying stuck. Queueing the same Scan twice while the first still waits queues it once.

Each Engine has a timeout (`HQ_ENGINE_TIMEOUT_SECS`, default 600). Past it the subprocess is killed and the Engine counts as failed — which fails the Gate closed. A scanner that hangs must never read as a clean Target. See [ADR 0021](docs/adr/0021-scan-queue.md).

### Remediations

For an SCA Finding with a known fixed version, HQ prepares the pin and opens it as a pull request on the default Revision — one package, one PR, whatever it fixes, so a bad `minimist` bump never blocks a good `lodash` one. The PR body lists every Finding the bump would Fixed, and the PR's own Gate is green for those Fingerprints, so it is mergeable.

HQ does not hand-write lockfiles. It checks the default Revision out, lets the ecosystem's own tool resolve the pin, and pushes the result as `hq/pin-<package>-<version>`:

| Ecosystem | How the pin is made |
|---|---|
| npm | A declared dependency is bumped where it is declared; a transitive one becomes an `overrides` entry, because a package the Target never declared is not ours to declare. `npm install --package-lock-only --ignore-scripts` resolves the lockfile. |

Anything else is reported as `unpinnable=<manifest>` and gets no PR. A placeholder edit that looks like a fix is worse than no fix. Secrets, SAST, and IaC still get no Remediation — HQ does not write source it cannot write safely.

### Workspaces

HQ gets the Revision on disk itself: a one-commit fetch of the exact branch or commit, into a temporary directory it removes when the Scan ends — including when an Engine fails. Private Targets work because the fetch carries the App's installation token, passed through git's environment rather than a remote URL, so nothing on disk and nothing in `ps` output holds a credential. A clone that fails is a failed Scan, never a clean Target.

Point it at a different host with `HQ_GITHUB_CLONE_BASE` (GitHub Enterprise), and pass `--workspace` to skip cloning entirely when you already have a checkout.

## Agent interface

HQ is built to be operated by humans *and* agents. Findings are machine-readable end to end:

```sh
hq findings --json --state open   # Open Findings, with agent_fixable flags
hq brief                          # next agent-fixable Finding as an Agent Brief
hq brief '<fingerprint>'          # a specific Finding as a Brief
hq show '<fingerprint>'           # one Finding as JSON
```

An agent reads a Brief, implements it, re-scans the Target, and verifies the Finding is no longer Open — no dashboard involved. See [docs/agents/domain.md](docs/agents/domain.md).

## Status

First release: **Code**. Cloud, Attack, and Protect are next. Architecture decisions live in [docs/adr/](docs/adr/); [CONTEXT.md](CONTEXT.md) holds the canonical glossary of domain terms.

## Development

```sh
cargo test     # unit + integration tests against a local Postgres
```

## License

MIT. Engine binaries and rules carry their own licenses (see the table above).
