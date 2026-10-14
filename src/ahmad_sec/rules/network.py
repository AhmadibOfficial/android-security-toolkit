def analyze_network(apk):
    findings = []

    manifest = apk.get_android_manifest_xml()
    application = manifest.find("application")

    if application is None:
        return findings

    attr = "{http://schemas.android.com/apk/res/android}usesCleartextTraffic"

    if application.get(attr) == "true":
        findings.append({
            "severity": "MEDIUM",
            "title": "Cleartext traffic enabled",
            "cwe": "CWE-319",
        })

    return findings
