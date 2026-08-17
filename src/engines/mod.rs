//! Real Engine adapters. Each turns a local binary's output into Observations.
//! HQ tests use FakeEngine; these adapters have their own contract tests.

pub mod gitleaks;
pub mod opengrep;
pub mod trivy;
