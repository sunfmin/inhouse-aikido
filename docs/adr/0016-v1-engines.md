# Code v1 Engines are Semgrep, Gitleaks, and Trivy

The first adapter set is Semgrep Community Edition for SAST, Gitleaks (the CLI) for secrets, and Trivy for SCA, license, IaC, and images. Engines stay swappable (ADR-0002). We rejected seven best-of-breed adapters and Trivy-for-secrets.

Licenses, verified from GitHub SPDX: Semgrep engine LGPL-2.1, Gitleaks CLI MIT, Trivy Apache-2.0. None of the three is MIT-only. Semgrep-maintained *rules* use the Semgrep Rules License v1.0 (not OSI) — that choice is still open.
