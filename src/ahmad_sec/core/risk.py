def calculate_risk(finding):
    severity = finding.get("severity", "INFO").upper()
    confidence = finding.get("confidence", "MEDIUM").upper()

    severity_score = {
        "CRITICAL": 10,
        "HIGH": 8,
        "MEDIUM": 5,
        "LOW": 2,
        "INFO": 0,
    }.get(severity, 0)

    confidence_multiplier = {
        "HIGH": 1.0,
        "MEDIUM": 0.75,
        "LOW": 0.5,
    }.get(confidence, 0.75)

    return round(severity_score * confidence_multiplier, 2)
