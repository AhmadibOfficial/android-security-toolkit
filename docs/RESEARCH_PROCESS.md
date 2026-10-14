# AHMAD-IB Security Research Process

**Principle:** Not every vulnerability matters. Fix the ones that do.

1. **Scope:** use self-owned training apps, open-source targets with clear rules, or other explicitly authorized assessments.
2. **Hypothesis:** record version, component, trust boundary, suspected security impact, and why it matters.
3. **Evidence:** reproduce with sanitized fixtures. Preserve reproducible steps and relevant code locations. Do **not** commit actual keys, customer data, private APKs, or exploit payloads for live targets.
4. **Validation:** distinguish `observed configuration`, `candidate risk`, and `confirmed exploitable vulnerability`; confidence is not exploitability.
5. **Prioritize:** consider authorization boundary, reachability, impacted data/operations, prerequisites, and practical remediation. Do not classify exported components or WebView use alone as vulnerabilities.
6. **Private report:** disclose through the maintainer's security policy or the in-scope bug bounty process. Never automate submission or public disclosure.
7. **Fix and retest:** write a regression test, confirm remediation in an authorized environment, and document affected and fixed versions.
8. **Publication:** publish only after coordinated disclosure approval and applicable embargoes. Reference approved advisory/CVE where appropriate.

## Evidence record template

| Field | Description |
|---|---|
| `rule_id` | Stable detector identifier, e.g. AST-SEC-001 |
| `asset` | Authorized app and version (avoid confidential project identifiers) |
| `sha256` | Hash of analyzed artifact; do not publish artifact without permission |
| `finding_state` | observation / candidate / confirmed / remediated |
| `severity` | Contextual impact rating, not a promise of exploitability |
| `confidence` | Strength of evidence supporting the detection |
| `evidence` | Redacted manifest/code evidence, sanitized path/line |
| `reproduction` | Steps reproducible on lab copy without external targets |
| `impact` | Demonstrated impact with its assumptions and limits |
| `mitigation` | Actionable fix and retest notes |
| `disclosure_status` | private / triaged / fixed / approved for publication |

### Current known limitations

- APK secret scanning covers only selected UTF-8 resource-like files; it does not establish absence of secrets from DEX or native code.
- The existing component detector must be validated for individual component attributes, effective export defaults, intent filters, permissions, and disabled components before its output is security-grade.
- Cleartext configuration is a potential risk signal, not evidence that sensitive data actually travels in plaintext.
- Never display a full matching secret in CLI output or CI logs; redaction is a pre-publication engineering task.
