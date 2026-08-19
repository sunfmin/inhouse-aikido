# 0027 — An agent does not grade its own fix

Status: accepted

## Context

HQ's agent loop was built around one kind of fix: a dependency pin. For that
case the Agent Brief could be terse, because the change is mechanical — the
Brief names the package and the version, and the agent edits one line.

Everything else HQ finds is not mechanical. A SAST rule fires on a code path;
an IaC rule fires on a setting. The Brief for those said which rule fired and
where, and then left the agent to open the file, guess which of the lines the
rule meant, and decide for itself whether it had fixed anything.

That produced two failures we care about.

The first is the *silent no-op*: the agent edits something adjacent, re-reads
its own diff, decides it looks right, and reports the Finding fixed. Nothing
re-ran the Engine. The Finding is still there.

The second is *collateral*: the agent removes the `eval` and shells out
instead. The named Finding really is gone, and the tree is no safer. An agent
that only checks the Finding it was given calls that a success.

There is also a standing temptation we want closed off: the fastest way to
make a SAST rule stop firing is a suppression comment. That is a fix to the
report, not to the code.

## Decision

**HQ decides whether a Finding is fixed, by re-running the Engines.**
`hq verify '<fingerprint>'` re-scans the Finding's Target at the Revision the
Finding was last seen on, folds the result into state, and reports what is
really there. It exits non-zero while the Finding is still Open, so an agent
loop branches on an exit code rather than on its own reading of its diff.

**Verify reports collateral.** It records which Findings were Open before the
re-scan, and names any that are Open after and were not before. A Finding that
is Fixed with new Findings alongside it exits non-zero too.

**Verify reports; it does not act.** It runs the Engines and applies the
result, and deliberately skips the rest of a Scan: no Remediation is opened, no
digest is posted. Verifying is a question, and asking a question should not
change anything a person will be paged about.

**An Engine that fails is not a pass.** If any selected Engine fails, verify
errors and leaves the Finding's state alone. "The scanner crashed" must never
read as "the problem is gone".

**What a failed verify learned is still saved.** The re-scan is real work — new
Findings it turned up are recorded before the non-zero exit.

**The Brief carries the code.** For SAST and IaC Findings, HQ captures the
offending line with three lines either side at Scan time, marks the offending
line, and renders it in the Brief as a fenced block. The agent sees what it is
fixing without opening the file, and cannot mistake which line the rule meant.

**A secret's line is never captured.** Snippet capture is restricted to SAST
and IaC by construction — not by filtering later. A Brief that quoted the
credential would leak it into every place a Brief goes.

**Suppression is a named non-goal.** The SAST and IaC Briefs list silencing the
rule with an ignore comment under "Out of scope", next to dismissing it.

## Consequences

Verify costs a full Engine run of the Target, not just of the one file. That is
the point — it is the same run the Gate does, so passing verify means the same
thing as passing the Gate.

Verify writes to state. Two agents verifying the same Target concurrently race
the same way two Scans do, and are serialised by the same advisory lock.

The snippet is captured at Scan time and stored on the Observation, so a Brief
read long after the Scan shows the code as it was when the Engine saw it, not
as it is now. For an agent about to edit that file, the Engine's view is the
one that matters.
