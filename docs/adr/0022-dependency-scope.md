# 0022 — Dependency Scope is HQ's, read from the Target's manifests

## Status

Accepted

## Context

Most of what a dependency scanner reports on a healthy Target is a CVE in
something that never ships: a test runner, a bundler, a linter's transitive
dependency. Blocking a merge on it teaches Developers that the Gate is noise,
which is the failure mode that ends with the Gate turned off.

Scope is the highest value-per-line de-noising available, and it is cheap:
the Target's own package manager already worked out which dependencies are
reachable only through development, and wrote it into the lockfile.

The alternative is to take Scope from the Engine. Trivy can be told to include
dev dependencies, but what it reports back is a vulnerability list, not a scope
per package, and every Engine would have to be taught separately.

## Decision

Scope is HQ's, derived from the Target's manifests in the workspace the Scan has
already cloned.

- `Scope` is `Runtime`, `Development`, or `Unknown`, on the Observation. An
  Engine that does report Scope keeps it; HQ fills in the rest.
- **Unknown Gates like Runtime.** HQ de-noises on evidence, never on a guess. An
  unreadable lockfile, an ecosystem HQ has no reader for, a Scan with no
  workspace — all stay Unknown and all keep blocking merges.
- **A Finding is development-scope only when every Engine that saw it said so.**
- **Runtime wins across the Target.** A package that is a runtime dependency in
  any manifest is runtime in all of them, so a monorepo's test app cannot
  quietly de-noise the API's copy of the same library.
- **Development-scope Findings are de-noised, not hidden.** Still Open, still in
  `hq findings`, still annotated on the PR — as a `warning` that names the
  scope rather than a `failure`.
- **Scope is not part of the Fingerprint** (ADR 0007). A package moved from
  `devDependencies` to `dependencies` is the same Finding; it just starts
  blocking merges.
- An Operator can set `gate_dev_scope` per Target (`hq policy`), for a Target
  that ships its build output.

npm is the first reader: lockfile v2/v3's `packages` map and v1's `dependencies`
tree both carry npm's own `dev` flag, at any depth. `package.json` alone is the
fallback when there is no lockfile.

## Consequences

Every new ecosystem needs a reader, and until it has one its Findings stay
Unknown — which is safe, but means the de-noising arrives per ecosystem rather
than all at once.

Scope is computed at Scan time from the Revision being scanned, so it is as
current as the Scan. A Finding whose Scope changed is re-recorded on the next
Scan of the default Revision.

This changes what the Gate blocks on, not how Findings are ranked. Severity and
exploitability are a separate axis, and land next.
