"""Synthetic tests for packaged Network Security Config resource analysis."""

from xml.etree import ElementTree

from ahmad_sec.rules.network import analyze_network

ANDROID_NS = "http://schemas.android.com/apk/res/android"


class SyntheticAPK:
    def __init__(self, xml, reference="@xml/network_security_config", target=35, paths=None,
                 cleartext=None, debuggable="false", resolver=None):
        attrs = f' android:networkSecurityConfig="{reference}"'
        if cleartext is not None:
            attrs += f' android:usesCleartextTraffic="{cleartext}"'
        attrs += f' android:debuggable="{debuggable}"'
        self.manifest = ElementTree.fromstring(
            f'<manifest xmlns:android="{ANDROID_NS}"><application{attrs}/></manifest>'
        )
        self.xml = xml.encode() if isinstance(xml, str) else xml
        self.paths = paths if paths is not None else ["res/xml/network_security_config.xml"]
        self.resolver = resolver
        self.target = target

    def get_android_manifest_xml(self):
        return self.manifest

    def get_files(self):
        return self.paths

    def get_file(self, path):
        assert path in self.paths
        return self.xml

    def get_package(self):
        return "org.example.lab"

    def get_target_sdk_version(self):
        return str(self.target)

    def get_android_resources(self):
        return self.resolver


def test_base_cleartext_explicitly_permitted():
    apk = SyntheticAPK('<network-security-config><base-config cleartextTrafficPermitted="true"/></network-security-config>')
    findings = analyze_network(apk)
    assert len(findings) == 1
    assert findings[0]["id"] == "AST-NET-CLEARTEXT-BASE"
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["file"] == "res/xml/network_security_config.xml"


def test_domain_override_and_nested_inheritance():
    apk = SyntheticAPK(
        '<network-security-config>'
        '<base-config cleartextTrafficPermitted="false"/>'
        '<domain-config cleartextTrafficPermitted="true">'
        '<domain includeSubdomains="true">example.test</domain>'
        '<domain-config cleartextTrafficPermitted="false"><domain>secure.example.test</domain></domain-config>'
        '</domain-config></network-security-config>'
    )
    findings = analyze_network(apk)
    cleartext = [f for f in findings if "Cleartext permitted" in f["title"]]
    assert len(cleartext) == 1
    assert "example.test" in cleartext[0]["component"]
    assert cleartext[0]["severity"] == "MEDIUM"


def test_config_parsed_when_manifest_flag_is_missing():
    apk = SyntheticAPK(
        '<network-security-config><domain-config cleartextTrafficPermitted="true">'
        '<domain>api.example.test</domain></domain-config></network-security-config>'
    )
    assert any("api.example.test" in f.get("component", "") for f in analyze_network(apk))


def test_trust_pinning_debug_override_are_observations():
    apk = SyntheticAPK(
        '<network-security-config><base-config><trust-anchors>'
        '<certificates src="user" overridePins="true"/>'
        '</trust-anchors></base-config>'
        '<domain-config><domain>example.test</domain>'
        '<pin-set expiration="2027-01-01"><pin digest="SHA-256">AAAA</pin></pin-set>'
        '</domain-config><debug-overrides><trust-anchors>'
        '<certificates src="@raw/debug_ca"/>'
        '</trust-anchors></debug-overrides></network-security-config>'
    )
    titles = {f["title"] for f in analyze_network(apk)}
    assert "Custom or user trust anchor requires review" in titles
    assert "Certificate pinning configuration observed" in titles
    assert "Debug trust overrides declared" in titles


def test_missing_xml_never_claims_success():
    apk = SyntheticAPK("<network-security-config/>", paths=[])
    findings = analyze_network(apk)
    assert len(findings) == 1
    assert findings[0]["id"] == "AST-SEC-001-CONFIG"
    assert "review" in findings[0]["title"].lower()


def test_multiple_resource_variants_need_device_specific_review():
    apk = SyntheticAPK(
        "<network-security-config/>",
        paths=["res/xml/network_security_config.xml",
               "res/xml-v28/network_security_config.xml"],
    )
    findings = analyze_network(apk)
    assert len(findings) == 1
    assert "Multiple resource variants" in findings[0]["assessment"]


def test_malformed_resource_fails_closed():
    apk = SyntheticAPK("<network-security-config>")
    findings = analyze_network(apk)
    assert len(findings) == 1
    assert findings[0]["id"] == "AST-SEC-001-CONFIG"
    assert "Could not parse" in findings[0]["assessment"]


def test_older_target_sdk_default_is_informational():
    apk = SyntheticAPK("<network-security-config/>", target=23)
    findings = analyze_network(apk)
    assert [f["id"] for f in findings] == ["AST-NET-CLEARTEXT-DEFAULT"]
    assert findings[0]["severity"] == "INFO"


def test_non_permissive_config_not_reported_as_vulnerable():
    apk = SyntheticAPK(
        '<network-security-config><base-config cleartextTrafficPermitted="false"/>'
        '</network-security-config>'
    )
    assert analyze_network(apk) == []


class FakeResources:
    def get_resolved_res_configs(self, resource_id):
        assert resource_id == 0x7F120001
        return [(None, "res/xml/obfuscated.xml")]


def test_numeric_resource_reference_resolution():
    apk = SyntheticAPK(
        '<network-security-config><base-config cleartextTrafficPermitted="true"/>'
        '</network-security-config>',
        reference="@0x7f120001",
        paths=["res/xml/obfuscated.xml"],
        resolver=FakeResources(),
    )
    assert analyze_network(apk)[0]["id"] == "AST-NET-CLEARTEXT-BASE"
