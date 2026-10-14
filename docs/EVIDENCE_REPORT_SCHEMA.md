# Structured evidence report (AST-018)

The optional CLI flag writes a deterministic JSON report beside the regular terminal
assessment:

```bash
ahmad-sec apk scan /path/to/authorized.apk --json-out evidence-local.json
```

The output file is created exclusively (no silent overwrite) with owner-only
permissions on POSIX systems. Treat it as potentially sensitive research data:
do **not** commit evidence files or disclose them publicly without review.

## Schema 1.0

- `schema_version`: JSON report schema.
- `assessment_type`: `offline_static`; no device exploitation is performed.
- `target`: APK filename (not full host path), package, SHA-256 and target SDK.
- `summary`: total observations and severity counts.
- `findings[].instance_id`: deterministic fingerprint derived from rule, source,
  affected component, and original observation. It is not a CVE or vulnerability ID.
- `findings[].rule_id`: stable toolkit rule identifier.
- `findings[].severity` and `confidence`: distinct assessments.
- `findings[].evidence.observation`: displayed evidence with known credential
  patterns redacted; includes collection method and source filename.
- `findings[].validation_status`: `observation` or `requires_manual_validation`.
  The CLI never marks issues as confirmed vulnerabilities.

## Limitations and required review

Pattern redaction cannot guarantee removal of all real secrets. Review every
report before sending it externally. Network policy findings describe
configuration observations rather than proven HTTP traffic or TLS bypasses.
Resource variants and unparseable XML require manual follow-up. An authorized
security researcher must investigate reachability, impact and remediation.

Reports intentionally omit timestamps to support reproducibility and do not
include raw APK bytes, credentials, or absolute host paths.
