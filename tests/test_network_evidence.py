"""Synthetic Network Security Config regression tests (no third-party APKs)."""

from xml.etree import ElementTree

from ahmad_sec.rules.network import analyze_network

ANDROID_NS = "http://schemas.android.com/apk/res/android"


class SyntheticAPK:
    def __init__(self, cleartext=None, network_config=None, has_application=True):
        attrs = []
        if cleartext is not None:
            attrs.append(f'android:usesCleartextTraffic="{cleartext}"')
        if network_config is not None:
            attrs.append(f'android:networkSecurityConfig="{network_config}"')
        app = f'<application {" ".join(attrs)}/>' if has_application else ""
        self.xml = ElementTree.fromstring(
            f'<manifest xmlns:android="{ANDROID_NS}">{app}</manifest>'
        )

    def get_android_manifest_xml(self):
        return self.xml


def test_explicit_cleartext_reports_manifest_evidence_not_exploitation():
    findings = analyze_network(SyntheticAPK("true"))
    assert len(findings) == 1
    assert findings[0]["title"] == "Cleartext traffic enabled"
    assert findings[0]["id"] == "AST-SEC-001"
    assert findings[0]["cwe"] == "CWE-319"
    assert findings[0]["evidence"] == 'android:usesCleartextTraffic="true"'
    assert "not been verified" in findings[0]["assessment"]


def test_explicit_false_does_not_flag():
    assert analyze_network(SyntheticAPK("false")) == []


def test_network_security_config_requires_review_not_medium_finding():
    findings = analyze_network(SyntheticAPK("true", "@xml/network_security_config"))
    assert len(findings) == 1
    assert findings[0]["severity"] == "INFO"
    assert findings[0]["confidence"] == "HIGH"
    assert findings[0]["id"] == "AST-SEC-001-CONFIG"
    assert "@xml/network_security_config" in findings[0]["evidence"]
    assert "Parse the referenced config" in findings[0]["assessment"]


def test_missing_flag_does_not_claim_application_is_secure():
    assert analyze_network(SyntheticAPK()) == []


def test_no_application_does_not_crash():
    assert analyze_network(SyntheticAPK(has_application=False)) == []
