from xml.etree import ElementTree as ET
from ahmad_sec.rules.secrets import scan_text
from ahmad_sec.rules.components import analyze_components

ANDROID = 'http://schemas.android.com/apk/res/android'


def test_potential_secret_evidence_is_redacted():
    synthetic = 'AIza' + 'Z' * 35  # no real credential
    findings = scan_text('sample=' + synthetic)
    assert findings, 'Synthetic potential secret was not detected'
    assert synthetic not in repr(findings), 'Raw potential secret leaked into report output'


class FakeAPK:
    def get_android_manifest_xml(self):
        return ET.fromstring(
            '<manifest xmlns:android="' + ANDROID + '" package="example.lab">'
            '<application>'
            '<activity android:name="example.lab.Public" android:exported="true"/>'
            '<activity android:name="example.lab.Private" android:exported="false"/>'
            '</application></manifest>'
        )

    def get_activities(self):
        return ['example.lab.Public', 'example.lab.Private']

    def get_services(self):
        return []

    def get_receivers(self):
        return []

    def get_providers(self):
        return []

    def get_attribute_value(self, *args):
        # Deliberately non-component-specific: the analyzer must use the manifest
        # element's own attributes, never reuse a global/exported first match.
        return 'true'


def test_component_exposure_is_per_component():
    findings = analyze_components(FakeAPK())
    names = {item.get('component') for item in findings}
    assert 'example.lab.Public' in names
    assert 'example.lab.Private' not in names, 'Private component incorrectly marked as exported'
    assert all(item['severity'] == 'INFO' for item in findings)
