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
The person who changes the code a Finding is about. They see Findings as PR annotations and can Dismiss them.
_Avoid_: user, engineer (when you mean this role)

**Operator**:
The person who configures Engines and rules, reviews the Dismissed list, and Reopens. They are not the inbox for Findings.
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
A Developer's or Operator's decision on a Finding: do not nag this Target for this Fingerprint, and do not fail the Gate, until someone Reopens it.
_Avoid_: ignored, accepted, suppressed, wontfix (when you mean Dismissed)

**Reopen**:
An Operator decision that turns a Dismissed Finding back to Open.
_Avoid_: restore, unignore, activate

**Observation**:
One Engine's report that supports a Finding.
_Avoid_: result, match, hit (when you mean an Observation)

**Target**:
A durable asset HQ tracks — a GitHub repo or an image repo. Later, a cloud account. Not a commit and not a lockfile line. A Target exists only after Enrollment.
_Avoid_: asset, project, resource (when you mean a Target)

**Enrollment**:
The Operator or repo-admin act that makes a repo or image repo a Target. The first Scan of the default Revision writes the Baseline and fails nothing; the Gate starts after that.
_Avoid_: install, connect, onboard (when you mean Enrollment)

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

**Remediation**:
A pull request HQ opens against the Target's default Revision after Baseline exists, applying a concrete safe edit (a dependency pin to a known fixed version). Secrets, SAST, and IaC do not get a Remediation in the first release.
_Avoid_: autofix, patch, bot PR (when you mean a Remediation)
