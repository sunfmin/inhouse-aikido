# 0024 — A leaked credential is checked against its own provider, and only that

## Status

Accepted

## Context

Every secret Finding looked the same: a key rotated last year and a key somebody
can use right now. They are not the same problem, and treating them the same
costs both ways. Dead keys make the Gate noisy enough to be ignored; live ones
sit on a Baseline as accepted debt, which is exactly what a live credential must
never be.

The provider knows. Every credential API has a cheap read-only identity call —
`GET /user`, `whoami`, `auth.test` — that answers the only question HQ has.

Asking it means HQ sends a Target's credential to a third party. That is a real
decision, and not one HQ gets to make on an Operator's behalf.

## Decision

HQ can verify a leaked credential against its own provider, and does not unless
told to.

- `Validity` is `Active`, `Inactive`, or `Unverified`, on the Finding.
- **Off by default.** `--verify-secrets real` turns it on. Off, every secret is
  Unverified and HQ behaves exactly as it did before.
- **One read-only identity call, to the provider the credential belongs to and
  nowhere else.** Never a call that could change the account. Which provider is
  decided by the token's own prefix, not by the Engine's rule name: prefixes are
  the provider's contract, rule names differ between Engines and versions.
- **The credential is never stored, logged, or printed.** It rides from the
  Engine adapter to the verifier on the Observation in a `LeakedSecret` that
  redacts itself in `Debug` and is skipped by serde, and is cleared before the
  Observation goes anywhere else. Only the verdict is persisted.
- **An active secret fails the Gate even on the Baseline.** A key somebody can
  use right now is an incident, not debt HQ agreed to live with.
- **An inactive secret does not fail the Gate on its own**, and sorts below
  everything else.
- **Unreachable is Unverified, never Inactive.** Calling a live key dead is the
  one wrong answer that lets a real incident through, so anything other than the
  provider explicitly rejecting the credential (401/403) leaves the verdict
  open.

GitHub, npm, Slack, and OpenAI are the first four. Adding another is one entry
in the registry: a prefix test and an endpoint.

## Consequences

Verification happens in the Scan's slow half, one call per leaked credential.
That is fine at the rate real Targets leak credentials, and would need batching
or caching if it ever stopped being.

Only Engines that report the matched value can be verified — gitleaks does,
which is the one that matters. Trivy's secret rules do not flow through this
path yet.

Because the credential is deliberately not persisted, a Finding's validity can
only be established while the Scan that found it is running. Re-verification is
a re-Scan, which is what `hq intel-rescan` already is.
