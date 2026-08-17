# HQ opens a Remediation only for a safe pin-bump, after Baseline

A Remediation is a PR on the default Revision that sets a dependency to a known fixed version. It never fires on Enrollment. Secrets, SAST, and IaC stay annotation-only in v1 — deleting a secret line is not a fix. We rejected "every new Finding gets a PR" and "the Gate's Finding gets a sibling bot PR."
