# Android Security Toolkit — Security Workspace Architecture

## Vision

Build a full Android application-security assessment workbench that combines real
static analysis, authorized runtime validation, exposure mapping, reproducible
evidence and risk-based reporting in a single desktop-friendly interface. The
dark, multi-panel operator console is a product direction, not proof that the
corresponding engines already exist.

**Core principle:** display only results produced by executed analyses and
label configuration observations separately from validated vulnerabilities.

## Current baseline (feature/security-workspace)

- Existing Python 3.11+ CLI: `ahmad-sec apk scan`, Androguard-based APK
  metadata analysis, manifest/components/network checks, selected secret checks.
- Existing redacted JSON evidence output (schema 1.0) with stable finding IDs,
  severity, confidence, observation, assessment and validation status.
- New loopback-only `ahmad-sec workspace` serves the bundled responsive UI.
  A local file chooser reads exported JSON entirely in the browser.
- Workspace panels: artifact intelligence, interactive attack-surface
  association graph, searchable severity-filtered findings, evidence inspector.
- Local HTTP service is read-only, binds to 127.0.0.1, permits only three
  bundled frontend assets and forbids cross-origin connections with CSP.
- Graph edges mean **reported association**, never confirmed exploitability.
- No reports, APKs, secret values, or account credentials are uploaded to the
  workspace server by this interface.

## Target analysis capabilities

| Domain | Target capability | Preconditions / proof standard |
| --- | --- | --- |
| Artifact ingestion | APK, AAB, APKS/split APK, signing/SDK metadata, SHA-256, reproducible job manifest | Validate format, resource bounds, and archive safety |
| Manifest and IPC | Components, effective exported state, permission protection levels, intent filters, deep links, ContentProvider access | Respect SDK-specific defaults and disabled entries |
| Bytecode and native | DEX code flow, insecure WebView patterns, Android keystore use, crypto implementations, native libraries/JNI | Evidence-backed rule tests and explicit confidence |
| Software supply chain | SBOM, library versions, advisory correlation, signing drift, binary diffs | Exact dependency evidence, verified advisories |
| Data protection | Local storage, logs, backup, accessibility, notifications, exposed data | Context-sensitive risks; redact customer data |
| Network security | Network security configuration, TLS policy, authorized capture and API endpoint inventory | No covert interception or unauthorized access |
| Device/runtime | Android emulator/ADB sessions, controlled test builds, instrumented lifecycle and deep-link validation | User-selected authorized test devices and applications |
| Analysis correlation | Static-to-runtime evidence linking, component graph, cross-run comparisons, risk triage | Every graph edge traceable to source evidence |
| Reporting | HTML/PDF, JSON/SARIF, MASVS/MASTG and CWE mapping, retest verification | Cite framework version and validation level |
| Integration | CLI, local UI, CI gates, GitHub check artifacts and audit events | Explicit opt-in; no hidden background scans |

These are **target capabilities**. The current workspace only provides local
JSON evidence review and interactive association mapping; it does not yet
perform device instrumentation, dynamic scans, APK uploads, network capture,
automated exploitation, or live scanning from the browser.

## Suggested system boundaries

```text
Operator UI (web assets served on localhost)
  | read-only evidence review initially
  | future authenticated local command API
  v
Assessment orchestrator (job lifecycle, scope, resource budgets)
  |-- Artifact validators (APK/AAB/split APK)
  |-- Static analyzers + rule pack
  |-- Authorized device and emulator adapter
  |-- Evidence store (redacted + encrypted where required)
  |-- Risk, correlation and provenance service
  |-- Report and integration exporters
  v
Local OS sandbox / selected emulator, with no default remote telemetry
```

Do not connect browser controls to arbitrary shell commands. Future scanning
APIs must validate a selected artifact, prevent path traversal, constrain jobs
and resource use, and require a user action per target. Avoid localhost
CSRF/dns-rebinding vulnerabilities: check Origin and Host, require session
tokens for state-changing actions, disable CORS, and keep loopback binding.

## Engineering milestones

1. **Workspace foundation** (this branch): usable locally, interactive
   reporting from real JSON, responsive visual system and safe packaging.
2. **Evidence engine strengthening**: redact raw observations before UI,
   prove manifest detector correctness, archive limits, signing and DEX inventory,
   regression fixtures, accurate reachability/false-positive accounting.
3. **Scan job service**: authenticated loopback service, artifact selector,
   bounded asynchronous jobs, cancellation, progress, history and SQLite
   evidence records. Explicit authorization scope per scan.
4. **Application surface graph**: typed nodes for activities/services/providers,
   endpoints, permissions, storage, API operations and findings; provenance for
   every edge; zoom, drill-down, diff and evidence linking.
5. **Runtime lab integration**: safe ADB/emulator control, instrumented
   observability, network traffic visualization and secure evidence collection
   with operator consent.
6. **Professional validation and releases**: reproducible MASVS/MASTG case
   mapping, human triage, retesting, SARIF/CI integrations, full security,
   accessibility and packaging reviews.

## Acceptance gates

- Every metric resolves to a real report, with no prefilled incident data.
- Imported report version and size are validated; all untrusted strings are
  rendered as text rather than HTML.
- Invalid / malicious archives and reports cannot access arbitrary files or
  execute browser code.
- Local service rejects unknown paths and POST, binds only to loopback,
  returns no-store and security headers.
- Results explicitly distinguish observation, candidate and confirmed issue.
- No sensitive evidence or third-party APKs are checked into Git.
- Automated tests, linting, responsive/mobile keyboard navigation and
  independent security review are required before release.
