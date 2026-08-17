# HQ is a GitHub App

HQ authenticates to GitHub as an App installed on the org. That identity annotates PRs, fails the Gate, and opens Remediation PRs. We rejected a personal access token (dies with the person) and GITHUB_TOKEN-only (cannot open a 3am Remediation or re-scan when intel changes).
