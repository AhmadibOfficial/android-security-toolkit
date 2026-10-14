from ahmad_sec.core.risk import calculate_risk


def test_high_confidence_high_severity():
    assert calculate_risk({"severity": "HIGH", "confidence": "HIGH"}) == 8.0


def test_info_never_escalates():
    assert calculate_risk({"severity": "INFO", "confidence": "HIGH"}) == 0.0


def test_medium_confidence_discount():
    assert calculate_risk({"severity": "MEDIUM", "confidence": "MEDIUM"}) == 3.75
