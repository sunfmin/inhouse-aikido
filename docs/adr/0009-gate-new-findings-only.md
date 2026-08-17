# The Gate fails only on new Open Findings

A PR is blocked when it introduces a Fingerprint that is not already Open or Dismissed on the Target's default Revision. Pre-existing debt stays visible and does not fail CI. We rejected "any Open Finding blocks" (rollout freeze) and informational-only (not a Gate). v1 has no severity split — a new Finding is a new Finding.
