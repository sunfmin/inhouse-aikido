# HQ remembers; CI gates the merge

A long-lived HQ holds inventory and findings and re-scans when Engine intel changes, so a 3am CVE does not wait for the next PR. CI on our runners still gates the merge. We rejected CI-only (no memory) and HQ-only (cannot block a merge).
