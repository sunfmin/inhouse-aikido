# A Fingerprint ignores Engine, line number, and package version

Two Observations match one Finding when they share Target + problem id (CVE or rule) + location key (package or file path). A rebase that moves a line, a second Engine, or a version bump that still carries the same CVE must not open a new Finding. We rejected engine-native IDs (never merge) and version-in-the-key (every bump is new work).
