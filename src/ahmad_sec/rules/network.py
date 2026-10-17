"""Evidence-led Android manifest network-security observations."""

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def analyze_network(apk):
    """Report explicit cleartext opt-in without asserting exploitable traffic.

    A Network Security Config can determine effective cleartext behavior on
    Android 7.0+; its referenced XML is not yet parsed by this analyzer.
    """
    root = apk.get_android_manifest_xml()
    application = root.find("application") if root is not None else None
    if application is None:
        return []

    flag = application.get(f"{{{ANDROID_NS}}}usesCleartextTraffic")
    if flag != "true":
        return []

    config = application.get(f"{{{ANDROID_NS}}}networkSecurityConfig")
    if config:
        return [{
            "id": "AST-SEC-001-CONFIG",
            "severity": "INFO",
            "confidence": "HIGH",
            "title": "Cleartext setting requires Network Security Config review",
            "cwe": "CWE-319",
            "evidence": (
                'android:usesCleartextTraffic="true"; '
                f'android:networkSecurityConfig="{config}"'
            ),
            "assessment": (
                "On Android 7.0+, Network Security Config can control the "
                "effective cleartext policy and the manifest flag may be "
                "ignored. Parse the referenced config and verify traffic "
                "before describing this as an exploitable weakness."
            ),
        }]

    return [{
        "id": "AST-SEC-001",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "title": "Cleartext traffic enabled",
        "cwe": "CWE-319",
        "evidence": 'android:usesCleartextTraffic="true"',
        "assessment": (
            "The manifest explicitly opts in to cleartext traffic. "
            "Actual HTTP usage and exploitability have not been verified."
        ),
    }]
