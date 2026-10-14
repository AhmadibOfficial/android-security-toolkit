from xml.etree import ElementTree
from ahmad_sec.rules.manifest import analyze_manifest

ANDROID_NS = 'http://schemas.android.com/apk/res/android'


class SyntheticAPK:
    def __init__(self, attrs):
        attrib = ' '.join(f'android:{k}="{v}"' for k, v in attrs.items())
        self.xml = ElementTree.fromstring(
            f'<manifest xmlns:android="{ANDROID_NS}"><application {attrib}/></manifest>'
        )

    def get_android_manifest_xml(self):
        return self.xml


def test_explicit_debug_and_backup_are_detected():
    findings = analyze_manifest(SyntheticAPK({'debuggable': 'true', 'allowBackup': 'true'}))
    titles = {f['title'] for f in findings}
    assert 'Debuggable application' in titles
    assert 'Application backup enabled' in titles


def test_false_settings_not_flagged():
    assert analyze_manifest(SyntheticAPK({'debuggable': 'false', 'allowBackup': 'false'})) == []
