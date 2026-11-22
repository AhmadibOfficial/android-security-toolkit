"""Regression tests for manifest-derived attack surface inventory."""
import xml.etree.ElementTree as ET

import pytest

from ahmad_sec.analyzers.attack_surface import build_surface_map


def manifest(content, attrs=""):
    return ET.fromstring(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.sample"><application ' + attrs + ">" + content +
        "</application></manifest>"
    )


def test_exported_activity_and_link_graph():
    root = manifest('''<activity android:name=".Link" android:exported="true">
        <intent-filter android:autoVerify="true">
          <action android:name="android.intent.action.VIEW"/>
          <data android:scheme="https" android:host="example.com"/>
        </intent-filter>
    </activity>''')
    graph = build_surface_map(root, target_sdk=34)
    component = graph["components"][0]
    assert component["name"] == "com.sample.Link"
    assert component["exported"] is True
    assert component["filters"][0]["auto_verify"] is True
    assert any(e["relation"] == "declares_host" for e in graph["edges"])
    assert any(n["id"] == "uri_host:example.com" for n in graph["nodes"])
    assert graph["summary"]["deep_link_handlers"] == 1


def test_target_sdk_31_requires_export_for_filter():
    root = manifest('<activity android:name=".Link"><intent-filter>'
                    '<action android:name="a"/></intent-filter></activity>')
    item = build_surface_map(root, target_sdk=31)["components"][0]
    assert item["exported"] is None
    assert item["export_basis"] == "missing_exported_for_target_31_plus"


def test_inferred_defaults_and_app_disabled():
    root = manifest('<receiver android:name="R"/>'
                    '<service android:name=".Receiver" android:exported="true"/>',
                    'android:enabled="false"')
    comps = build_surface_map(root, target_sdk=30)["components"]
    assert [item["enabled"] for item in comps] == [False, False]
    assert {item["name"]: item["exported"] for item in comps} == {
        "com.sample.R": False, "com.sample.Receiver": True,
    }


@pytest.mark.parametrize("sdk,exported", [(16, True), (17, False), (None, None)])
def test_provider_default(sdk, exported):
    root = manifest('<provider android:name=".Data" android:authorities="com.sample.data"/>')
    item = build_surface_map(root, target_sdk=sdk)["components"][0]
    assert item["exported"] is exported


def test_permissions_and_no_false_vuln_claims():
    root = manifest('<provider android:name=".Data" android:exported="true" '
                    'android:readPermission="com.sample.READ"/>')
    graph = build_surface_map(root, target_sdk=30)
    assert any(n["id"] == "permission:com.sample.READ" for n in graph["nodes"])
    assert not any("vulnerabilit" in str(n).lower() for n in graph["nodes"])


def test_missing_manifest():
    with pytest.raises(ValueError):
        build_surface_map(None)


def test_deterministic_output():
    root = manifest('<activity android:name=".One" android:exported="true"/>')
    assert build_surface_map(root, target_sdk=33) == build_surface_map(root, target_sdk=33)
