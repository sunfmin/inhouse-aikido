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
A swappable scanner that examines a target on our runners and emits findings. Source never goes to a SaaS engine.
_Avoid_: scanner, tool, linter, plugin (when you mean an Engine)

**Developer**:
The person who changes the code a finding is about. They see findings as PR annotations.
_Avoid_: user, engineer (when you mean this role)

**Operator**:
The person who configures Engines, rules, and exceptions. They are not the inbox for findings.
_Avoid_: admin, security person (when you mean this role)

**HQ**:
The long-lived control plane that holds inventory and findings between scans, and re-scans when Engine intel changes.
_Avoid_: platform, dashboard, backend (when you mean the HQ)
