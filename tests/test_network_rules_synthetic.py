from xml.etree import ElementTree
from ahmad_sec.rules.network import analyze_network

ANDROID_NS = 'http://schemas.android.com/apk/res/android'


class SyntheticAPK:
    def __init__(self, cleartext):
        self.xml = ElementTree.fromstring(
            f'<manifest xmlns:android="{ANDROID_NS}">'
            f'<application android:usesCleartextTraffic="{cleartext}"/>'
            '</manifest>'
        )

    def get_android_manifest_xml(self):
        return self.xml


def test_cleartext_explicit_true_detected():
    findings = analyze_network(SyntheticAPK('true'))
    assert len(findings) == 1
    assert findings[0]['title'] == 'Cleartext traffic enabled'


def test_cleartext_explicit_false_not_flagged():
    assert analyze_network(SyntheticAPK('false')) == []
