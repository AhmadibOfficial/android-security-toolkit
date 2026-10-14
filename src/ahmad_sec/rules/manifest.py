ANDROID_NS = "http://schemas.android.com/apk/res/android"


def analyze_manifest(apk):
    findings = []
    manifest = apk.get_android_manifest_xml()

    application = manifest.find("application")

    if application is None:
        return findings

    if application.get(f"{{{ANDROID_NS}}}debuggable") == "true":
        findings.append({
            "id": "AST-SEC-002",
            "severity": "HIGH",
            "confidence": "HIGH",
            "title": "Debuggable application",
            "cwe": "CWE-489",
            "evidence": 'android:debuggable="true"',
        })

    if application.get(f"{{{ANDROID_NS}}}allowBackup") == "true":
        findings.append({
            "id": "AST-SEC-003",
            "severity": "MEDIUM",
            "confidence": "HIGH",
            "title": "Application backup enabled",
            "cwe": "CWE-921",
            "evidence": 'android:allowBackup="true"',
        })
    return findings
