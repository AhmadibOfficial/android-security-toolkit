"""Evidence reporting safety and reproducibility tests."""

import json
from pathlib import Path

import pytest
from typer.main import get_command

from ahmad_sec.cli import app
from ahmad_sec.reporting.evidence import build_evidence_report, write_evidence_report


METADATA = {
    "File": "/private/work/app.apk",
    "Package": "org.example.test",
    "SHA-256": "a" * 64,
    "Target SDK": 35,
}


def sample_finding():
    return {
        "id": "AST-SEC-005",
        "severity": "LOW",
        "confidence": "LOW",
        "title": "Potential Google API Key",
        "cwe": None,
        "component": None,
        "file": "assets/test.txt",
        "risk_score": 1,
        "evidence": "AIza" + "A" * 35,
        "assessment": "Unverified pattern match",
    }


def test_deterministic_fingerprint_and_no_local_path():
    r1 = build_evidence_report(METADATA, [sample_finding()])
    r2 = build_evidence_report(METADATA, [sample_finding()])
    assert r1 == r2
    serialized = json.dumps(r1)
    assert "/private/work" not in serialized
    assert "AIza" + "A" * 35 not in serialized
    assert "[REDACTED]" in serialized
    assert r1["findings"][0]["validation_status"] == "requires_manual_validation"
    assert r1["target"]["filename"] == "app.apk"


def test_repeated_findings_are_deduplicated():
    result = build_evidence_report(METADATA, [sample_finding(), sample_finding()])
    assert result["summary"]["total_observations"] == 1


def test_information_not_claimed_as_vulnerability():
    f = dict(sample_finding(), severity="INFO", risk_score=0)
    result = build_evidence_report(METADATA, [f])
    assert result["findings"][0]["validation_status"] == "observation"


def test_write_exclusive_and_private(tmp_path):
    output = tmp_path / "evidence.json"
    report = build_evidence_report(METADATA, [sample_finding()])
    write_evidence_report(output, report)
    assert json.loads(output.read_text()) == report
    assert output.stat().st_mode & 0o077 == 0
    with pytest.raises(FileExistsError):
        write_evidence_report(output, report)


def test_reject_symlink_output(tmp_path):
    real = tmp_path / "real.json"
    real.write_text("keep")
    link = tmp_path / "link.json"
    link.symlink_to(real)
    with pytest.raises(ValueError):
        write_evidence_report(link, {})
    assert real.read_text() == "keep"


def test_cli_exposes_json_out():
    # Check the registered Click option instead of terminal-width-dependent
    # Rich help output, which can shorten labels under GitHub Actions.
    scan = get_command(app).commands["apk"].commands["scan"]
    assert any("--json-out" in getattr(param, "opts", []) for param in scan.params)
