"""Deterministic, redacted evidence reports for authorized static assessments."""

import hashlib
import json
import re
from pathlib import PurePath

from ahmad_sec.rules.secrets import PATTERNS

SCHEMA_VERSION = "1.0"


def _mask(value):
    text = "" if value is None else str(value)
    for pattern in PATTERNS.values():
        text = re.sub(
            pattern,
            lambda match: match.group(0)[:4] + "...[REDACTED]..." + match.group(0)[-4:],
            text,
        )
    return text


def _archive_path(value):
    if not value:
        return None
    path = str(value).replace("\\", "/")
    if path.startswith("/") or any(part == ".." for part in path.split("/")):
        return "[path redacted]"
    return _mask(path)


def build_evidence_report(metadata, findings):
    """Create a reproducible JSON-safe report; no raw APK or local path embedded.

    Observations cannot be promoted to validated vulnerabilities by this function.
    Stable IDs help compare reruns without including timestamps or secrets.
    """
    meta = {str(key).lower().replace(" ", "_").replace("-", ""): value
            for key, value in metadata.items()}
    target = {
        "filename": PurePath(str(meta.get("file", "unknown"))).name,
        "package": _mask(meta.get("package")),
        "sha256": str(meta.get("sha256", "")),
        "target_sdk": str(meta.get("target_sdk", "unknown")),
    }
    observations = []
    seen = set()
    for finding in findings:
        original_evidence = str(finding.get("evidence") or "")
        source = _archive_path(finding.get("file"))
        component = _mask(finding.get("component"))
        stable = {
            "rule_id": str(finding.get("id") or "AST-SEC-UNCLASSIFIED"),
            "title": str(finding.get("title") or "Unspecified observation"),
            "component": str(finding.get("component") or ""),
            "source": source,
            "evidence": original_evidence,
        }
        fingerprint = hashlib.sha256(
            json.dumps(stable, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()[:20]
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        severity = str(finding.get("severity") or "INFO").upper()
        observations.append({
            "instance_id": "AST-" + fingerprint,
            "rule_id": stable["rule_id"],
            "title": _mask(stable["title"]),
            "severity": severity,
            "confidence": str(finding.get("confidence") or "MEDIUM").upper(),
            "risk_score": finding.get("risk_score", 0),
            "cwe": finding.get("cwe"),
            "component": component or None,
            "source_file": source,
            "evidence": {
                "kind": "static_configuration_or_pattern",
                "observation": _mask(original_evidence),
                "collection_method": "offline_apk_static_analysis",
            },
            "assessment": _mask(finding.get("assessment")),
            "validation_status": "observation" if severity == "INFO" else "requires_manual_validation",
        })

    observations.sort(key=lambda item: (
        -float(item["risk_score"]), item["rule_id"], item["instance_id"]
    ))
    severities = {k: 0 for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    for item in observations:
        severities[item["severity"]] = severities.get(item["severity"], 0) + 1
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": "ahmad-sec",
        "assessment_type": "offline_static",
        "target": target,
        "summary": {"total_observations": len(observations), "severity_counts": severities},
        "findings": observations,
        "limitations": [
            "Configuration and string-pattern evidence does not prove exploitation.",
            "Findings require authorized manual validation and context-specific triage.",
            "The scanner cannot guarantee that all embedded secrets are detected or redacted.",
        ],
    }


def write_evidence_report(path, report):
    """Write stable JSON with restrictive permissions on POSIX systems."""
    import os
    from pathlib import Path

    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.is_symlink():
        raise ValueError("Refusing to write evidence to a symbolic link")
    # O_EXCL prevents overwrites, including an existing symlink target.
    # Mode 0600 is applied at creation rather than after content is written.
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
