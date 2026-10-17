# Autonomous Engineering Policy

The security toolkit is maintained through a **fail-closed, approval-free routine engineering workflow**. This authorizes ordinary code improvements without asking the repository owner for each step. It does **not** authorize vulnerability disclosure, intrusive security testing, or uncontrolled infrastructure changes.

## Automated work

1. GitHub Actions runs a scheduled, source-only health build every day (Python 3.11 and 3.13).
2. The build compiles code, runs Ruff checks, executes synthetic regression tests, audits reachable Git history, verifies package dependencies, builds a wheel/sdist and checks installed dependencies for known vulnerabilities.
3. A scheduled failure creates or updates one tracking issue, rather than spamming duplicates. Successful rechecks close that issue.
4. Dependabot opens weekly update pull requests for Python dependencies and GitHub Actions.
5. Routine source improvements may be proposed and merged **without individual approval** when the change is narrowly scoped, reviewed against the current code, tests pass, its GitHub CI checks succeed, and the public release hygiene gate passes.

## Never automate

- Publishing actual third-party APKs, credentials, device tokens or unreviewed evidence reports.
- Submitting vulnerability reports, contacting affected vendors, or claiming a Hall-of-Fame or CVE acknowledgment without independent verification.
- Testing systems without scope authorization or launching active exploitation.
- Bypassing a failing test, CI check, branch protection, or license/rights restrictions to make a merge pass.
- Force-pushing or rewriting Git history, changing repository visibility, purchasing infrastructure, or provisioning paid services.

## Development sequence

Use a small feature branch and test the intended behavior on synthetic APK/Android-XML inputs. Distinguish configuration observations from verified vulnerabilities. Avoid duplicate or noisy findings. Merge to `main` only after passing checks and inspecting the changes. Prefer additive compatibility and reproducible reports. The automated GitHub jobs do not themselves use an LLM to write arbitrary code; AI-assisted engineering requires an authorized connected agent run.

## Private research evidence

Keep reports outside the repository (for example `~/.cache/ahmad-sec/reports`). Redaction by pattern is incomplete: reports must be inspected before disclosure. Never treat a score as CVSS or evidence of an exploit.

## GitHub settings recommendation

When available, protect `main` with required status checks and restrict direct pushes. GitHub repository settings are independent of this workflow; committing this policy does not activate branch protection.
