# 0025 — Malware is its own Finding kind, and HQ reads the inventory itself

## Status

Accepted

## Context

Every dependency Finding meant the same thing: somebody made a mistake in a
package you meant to install, and there is a version where they didn't. Bump it.

That is the wrong shape for a malicious package. There is no good version — the
package *is* the attack — so the fix is removal, and a pin Remediation is worse
than nothing. It also cannot sit on a Baseline: "we have agreed to live with
this" is a sentence about debt, and nobody agrees to live with malware.

The other half is typosquatting, where the package is not on any advisory list
yet and the only signal is that its name is one keystroke from something a
Developer plausibly meant to type.

Both need something HQ did not have: the Target's *whole* dependency list.
Engines report problems, not inventories — trivy names the packages with CVEs
and says nothing about the rest, and a typosquat has no CVE by definition.

## Decision

- **`FindingKind::Malicious`**, distinct from `Sca`. It sorts first, is never
  agent-fixable by a pin, and its Agent Brief says to remove the package and
  explicitly not to bump it.
- **It fails the Gate regardless of the Baseline**, like a live leaked
  credential (ADR 0024) and for the same reason.
- **No Remediation, ever** — not even for the package's ordinary CVEs. If a
  package is reported as malware, every version of it is, so its unrelated pins
  are skipped too.
- **HQ reads the inventory itself**, from the Target's lockfiles in the
  workspace the Scan already cloned (`inventory.rs`). Scope detection (ADR 0022)
  now shares that reader rather than parsing lockfiles a second time, and the
  SBOM will too.
- **Advisories are a port**, on the same switch as exploitability intel: both
  are public data about somebody else's packages, and an Operator who declines
  one declines the other. OSV is the first source; a `MAL-` id is what separates
  "this package has a bug" from "this package is the attack". One batched
  request per Scan, cached — including "asked, and it is clean".
- **A source that is down reports no malware** and does not fail the Scan.
- **Typosquat detection is local** and runs either way: Damerau-Levenshtein
  distance of exactly one from a list of names worth being one keystroke away
  from. Names shorter than four characters are never flagged — `ms` is one edit
  from half the registry.

A near-miss is a guess, so it is Dismissable like any other Finding, and a
Dismissed one stays Dismissed across re-Scans.

## Consequences

The popular-names list is a judgement call baked into the binary. It is not a
security list and does not need to be complete; missing a name means missing a
typosquat, never a false accusation about a real package.

Advisory coverage is only as good as OSV's malicious-package data, which is
better for npm than for most ecosystems. Everything here is npm-only until
`inventory.rs` learns another lockfile format — which is now the single place to
teach it.
