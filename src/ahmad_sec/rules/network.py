"""Network security observations from manifest and packaged NSC resources."""

from ahmad_sec.rules.network_config import analyze_network_config

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def analyze_network(apk):
    """Separate static manifest observations from resource-defined policies."""
    root = apk.get_android_manifest_xml()
    application = root.find("application") if root is not None else None
    if application is None:
        return []

    config = application.get(f"{{{ANDROID_NS}}}networkSecurityConfig")
    if config:
        return analyze_network_config(apk, config)

    flag = application.get(f"{{{ANDROID_NS}}}usesCleartextTraffic")
    if flag != "true":
        return []

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
