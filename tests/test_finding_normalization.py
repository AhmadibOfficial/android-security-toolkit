from ahmad_sec.core.finding import normalize_finding


def test_finding_has_consistent_fields_and_score():
    result = normalize_finding({
        "id": "AST-SEC-001", "severity": "medium", "confidence": "high",
        "title": "Synthetic cleartext configuration", "cwe": "CWE-319",
    })
    assert result["id"] == "AST-SEC-001"
    assert result["severity"] == "MEDIUM"
    assert result["confidence"] == "HIGH"
    assert result["risk_score"] == 5.0
    assert result["cwe"] == "CWE-319"


def test_empty_input_returns_information_finding():
    result = normalize_finding({})
    assert result["severity"] == "INFO"
    assert result["risk_score"] == 0.0
