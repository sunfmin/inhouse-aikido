# 0021 — Scans run on a queue, and HQ's write path is serialised

## Status

Accepted

## Context

A Scan is slow: a shallow clone plus one subprocess per Engine, seconds at best
and minutes on a large Target. Two things now ask for Scans faster than HQ can
run them.

A webhook delivery has to be answered in seconds. HQ already answers first and
works after (ADR 0020), but the work still happened inside the delivery handler,
one at a time — so a push storm across ten repos queued up behind whichever Scan
happened to be running, and a hung Engine stopped every other Target.

`hq intel-rescan` re-Scans every Target because intel moves: a CVE published
today makes yesterday's clean Scan wrong. Serially, a thousand Targets is a
command that runs for a day.

The obstacle to just running them concurrently is the Store. It loads all of
HQ's state and writes it all back, so two Scans finishing at once would clobber
each other — the second save would write back a snapshot taken before the first.

## Decision

Scans go on a durable queue in Postgres (`scan_jobs`), and workers claim them.

- **Claiming** is `UPDATE ... WHERE id = (SELECT ... FOR UPDATE SKIP LOCKED
  LIMIT 1)`. `SKIP LOCKED` is what makes two workers never take the same job,
  without a lock table of our own.
- **A Scan is split in half.** `observe` clones the Revision and runs the
  Engines; it writes nothing. `record` folds the Observations into Findings, and
  is the only half that writes. Workers do the slow half with nothing locked.
- **The write path is serialised** by a Postgres advisory lock, one per schema,
  taken around load → record → save. It is advisory rather than a mutex so it
  holds across processes: HQ is meant to run as several workers, not one.
- **A claimed job heartbeats.** A job whose heartbeat goes stale for longer than
  the lease goes back to `queued`, so a worker that dies does not strand a Scan.
- **Each Engine has a timeout.** Past it the subprocess is killed and the Engine
  is recorded as failed — which the Gate already knows how to treat: it fails
  closed. A hung scanner must never read as a clean Scan.
- **`hq scans`** shows what is queued, running, done, failed, or discarded, with
  the Target, Revision, Engines, how long it waited, and how long it took.

Enqueuing is idempotent: an identical Scan already waiting is not queued twice,
so a PR pushed to three times in a minute is one Scan of the head.

## Consequences

A delivery no longer blocks on Engines, and concurrency is a number
(`--workers`) rather than an accident. `hq work` is a long-running process, the
second one HQ has after `hq serve`; `hq serve` runs a pool itself by default so
a single-process deployment still works.

Because a queued Scan runs later, the world can change under it. A Target that
gets unenrolled between enqueue and run is discarded cleanly rather than
failing. The same is true of a Baseline that is not written yet.

The advisory lock means writes are still one at a time. That is deliberate for
now — the slow half is where the wall-clock is — but it is the thing to revisit
before the Store is asked to hold a large number of Targets. The Store rewriting
all state on every save is the underlying constraint; the lock makes that safe,
not fast.
