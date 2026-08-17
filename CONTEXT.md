# In-house Aikido

An in-house replacement of Aikido Security. The destination is feature parity with all four of Aikido's suites.

## Language

**Aikido**:
The commercial AppSec product at aikido.dev that this system replaces.
_Avoid_: the vendor, the platform, the scanner (when you mean the product)

**Suite**:
One of Aikido's four product surfaces. This system targets parity with all four: Code, Cloud, Attack, and Protect. The first release operates only Code.
_Avoid_: module, pillar, area (when you mean a Suite)

**Code**:
The Suite that scans what developers write and ship — source, dependencies, secrets, IaC, licenses, and container images.
_Avoid_: AppSec, repo scanning (when you mean this Suite)

**Engine**:
A swappable scanner that examines a Target on our runners and emits Observations. Source never goes to a SaaS engine.
_Avoid_: scanner, tool, linter, plugin (when you mean an Engine)

**Developer**:
The person who changes the code a finding is about. They see findings as PR annotations.
_Avoid_: user, engineer (when you mean this role)

**Operator**:
The person who configures Engines, rules, and exceptions. They are not the inbox for findings.
_Avoid_: admin, security person (when you mean this role)

**HQ**:
The long-lived control plane that holds inventory and Findings between scans, and re-scans when Engine intel changes.
_Avoid_: platform, dashboard, backend (when you mean the HQ)

**Finding**:
One problem on one kind of Target. Two Engines hitting the same lockfile CVE are one Finding; that CVE in the image is another.
_Avoid_: alert, issue, vuln, hit (when you mean a Finding)

**Fingerprint**:
The identity of a Finding: Target + problem id (CVE or rule) + location key (package name or file path). Not the line number, not the Engine, not the package version.
_Avoid_: hash, key, dedup id

**Open**:
A Finding whose latest Scan on that Target still produced an Observation, and that has not been Dismissed.
_Avoid_: active, new, unresolved (when you mean Open)

**Fixed**:
A Finding whose later Scan on that Target no longer produced an Observation.
_Avoid_: resolved, closed, gone (when you mean Fixed)

**Dismissed**:
A human decision on a Finding: do not nag this Target for this Fingerprint until someone reopens it.
_Avoid_: ignored, accepted, suppressed, wontfix (when you mean Dismissed)

**Observation**:
One Engine's report that supports a Finding.
_Avoid_: result, match, hit (when you mean an Observation)

**Target**:
A durable asset HQ tracks — a GitHub repo or an image repo. Later, a cloud account. Not a commit and not a lockfile line.
_Avoid_: asset, project, resource (when you mean a Target)

**Revision**:
The exact snapshot a Scan ran against — a git commit or an image digest.
_Avoid_: version, sha (when you mean a Revision)

**Scan**:
One Engine run against one Target at one Revision.
_Avoid_: job, check, analysis

**Baseline**:
The Fingerprints already Open or Dismissed on the Target's default Revision.
_Avoid_: snapshot, backlog, debt (when you mean the Baseline)

**Gate**:
The CI verdict on a PR. It fails only when the PR Revision has an Open Finding whose Fingerprint is not on the Baseline.
_Avoid_: check, status, block (when you mean the Gate)
