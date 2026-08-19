# 0026 — The SBOM comes from the Scan, and a license is a decision

## Status

Accepted

## Context

Two things an Operator gets asked for that HQ could not do.

An SBOM, because customers and procurement ask for one. The usual way to produce
it is to re-resolve the manifests at export time, which answers a slightly
different question — what the Target *would* resolve to today, not what the Scan
that produced these Findings actually saw.

And licenses. Trivy already reported them, and HQ turned each into a Finding
that said "this package is BSD-3-Clause" — true, and no help. Whether that is a
problem is a decision somebody at the company made, and HQ had nowhere to put it.

## Decision

**The SBOM is the Scan's inventory.** Every Scan with a workspace records what
the Target depends on (`target_packages`), replacing the previous Scan's list
wholesale so a removed dependency does not linger. `hq sbom <target>` writes
that as CycloneDX 1.5, with the scanned Revision as the metadata component's
version, so the document and the Findings describe the same moment.

A Target with no recorded inventory is an error, not an empty document. An
empty SBOM is a claim — "this Target has no dependencies" — and it is a very
different claim from "nobody has looked".

**A license is a policy question.** An Operator declares allow, deny, and review
lists (`hq license-policy`), stored by HQ rather than passed as a flag.

- **Allowed produces no Finding at all.** Not a Dismissed one, not a warning —
  nothing. The Operator has answered the question.
- **Denied Gates** like any other new Finding.
- **Review does not Gate.** It is Operator work, and blocking a merge on it
  would make somebody else's decision urgent for a Developer who cannot make it.
- **Unlisted means Review.** Unlisted is not consent, and HQ will not decide a
  licensing question on an Operator's behalf. This is why the default policy —
  no policy — leaves every license Open and blocking nothing.
- License Findings stay not-agent-fixable, so an agent asking for work is never
  handed one.

The Finding's message names the license and the rule it broke, so `hq findings`
answers "why is this here" without a second lookup.

## Consequences

The SBOM covers what `inventory.rs` can read, which is npm today. A Target whose
ecosystem has no reader has no SBOM rather than a partial one — the same
"nobody has looked" honesty as an unscanned Target.

License policy is HQ-wide rather than per-Target. A company with genuinely
different rules per repository would need it moved onto the Target, which is a
schema change and a flag, not a rethink.

Because allowed licenses produce no Observation, changing the policy to allow
something does not retire the existing Finding until the next Scan. That is the
same rule every other Finding follows: state changes when a Scan says so.
