from ahmad_sec.core.risk import calculate_risk


DEFAULTS = {
    "severity": "INFO",
    "confidence": "MEDIUM",
}


def normalize_finding(finding):
    normalized = {
        "id": finding.get("id", "AST-SEC-000"),
        "severity": finding.get("severity", DEFAULTS["severity"]).upper(),
        "confidence": finding.get("confidence", DEFAULTS["confidence"]).upper(),
        "title": finding.get("title", "Unspecified finding"),
        "cwe": finding.get("cwe"),
        "component": finding.get("component"),
        "evidence": finding.get("evidence"),
        "assessment": finding.get("assessment"),
    }

    normalized["risk_score"] = calculate_risk(normalized)

    return normalized
