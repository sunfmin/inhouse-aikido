# 0020 — HQ stays synchronous; blocking HTTP, threaded server

## Status

Accepted

## Context

Everything HQ does today is synchronous. The Store talks to PostgreSQL through
the blocking `postgres` client, Engines are subprocesses HQ waits on, and the
CLI is a single command that opens HQ, does one thing, saves, and exits.

The App work needs HQ to make outbound HTTP calls — mint a JWT, exchange it for
an installation token, write a Check Run, open a Remediation PR — and shortly
after, to receive inbound webhooks. The reflex is to reach for an async runtime,
because that is what most GitHub clients and every popular Rust web framework
assume.

Doing that would mean converting the Store to `tokio-postgres`, making every
method on HQ `async`, and colouring the whole codebase — for a workload whose
concurrency is bounded by how many repos we Scan, not by how many sockets we can
hold open. The Engines are subprocesses; they are not something an async runtime
makes faster.

## Decision

HQ stays synchronous end to end.

- Outbound HTTP: a blocking client (`ureq`, rustls, no OpenSSL).
- App JWTs: `jsonwebtoken` with RS256, on its pure-Rust `rust_crypto` provider.
  The `aws_lc_rs` alternative wants a C toolchain at build time, which is not
  worth it for signing one short-lived token per API burst.
- Inbound webhooks: a threaded HTTP listener, bounded by a pool — not an async
  runtime.
- Scan concurrency, when it arrives, is a worker pool over a Postgres-backed
  queue. Threads, not tasks.

No `async fn` in HQ, and no `tokio` in the dependency tree.

## Consequences

- The Store, the Engine adapters, and every existing HQ method keep working
  unchanged. There is no function colouring and no dual sync/async API.
- Each in-flight webhook or Scan costs a thread. At the scale HQ is for — an
  organisation's repos, not the public internet — a bounded thread pool is
  cheaper to reason about than an async runtime, and the Engines dominate the
  cost anyway.
- If HQ ever has to hold tens of thousands of idle connections, this decision
  has to be revisited. Nothing in the domain model depends on it, so that
  revisit is confined to the HTTP and queue layers.
- Rejected: `octocrab` and the other maintained Rust GitHub clients, because they
  are async. HQ calls a handful of GitHub endpoints and owns those requests
  directly.
