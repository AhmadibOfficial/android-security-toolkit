# Public release checklist

- [ ] `python -m pytest -q` passes across supported Python versions.
- [ ] `python scripts/release_audit.py --mode development` passes.
- [ ] `README.md`, `SECURITY.md`, and full SPDX-compatible `LICENSE` are populated.
- [ ] Replace risky raw-secret evidence output with masking; add regression tests.
- [ ] Validate exported-component observations with per-component manifest parsing; document platform defaults and permission protections.
- [ ] Validate findings with synthetic manifest fixtures and consented test apps.
- [ ] Confirm no APKs, credentials, personal data, or private target evidence in current tree.
- [ ] Create a **separate cleaned local clone**, remove prohibited historical blobs, and pass `--mode release`.
- [ ] Review history before opening GitHub repository; do not force-push blindly.
- [ ] Enable branch protection and require CI; retain minimal GitHub Actions permissions.
- [ ] Publish versioned release notes and a reproducible test report.
- [ ] Publish research only after responsible disclosure approval.

Never run an untrusted APK as part of CI. APK parsing must be isolated from secrets, external networks and privileged execution in any future large-scale scanning service.
