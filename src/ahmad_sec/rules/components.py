ANDROID_NS = "http://schemas.android.com/apk/res/android"


def analyze_components(apk):
    """Inventory explicitly exported components using per-element evidence.

    An exported component is informational until sensitive behavior and access
    controls are assessed. This does not infer defaults or exploitability.
    """
    findings = []
    root = apk.get_android_manifest_xml()
    app = root.find("application") if root is not None else None
    if app is None:
        return findings
    package = root.get("package", "")
    name_attr = f"{{{ANDROID_NS}}}name"
    export_attr = f"{{{ANDROID_NS}}}exported"
    permission_attr = f"{{{ANDROID_NS}}}permission"
    for element in app:
        kind = element.tag.rsplit("}", 1)[-1]
        if kind not in {"activity", "activity-alias", "service", "receiver", "provider"}:
            continue
        if element.get(export_attr) != "true":
            continue
        name = element.get(name_attr)
        if not name:
            continue
        if name.startswith("."):
            name = f"{package}{name}"
        elif "." not in name and package:
            name = f"{package}.{name}"
        permission = element.get(permission_attr) or app.get(permission_attr)
        assessment = (
            "Explicitly exported entry point. Exposure does not itself prove a vulnerability; "
            "review permission gates, entry-point data and sensitive code paths."
        )
        if permission:
            assessment += " A manifest permission is declared; validate its protection level."
        findings.append({
            "id": "AST-SEC-002-EXPOSURE", "severity": "INFO", "confidence": "HIGH",
            "title": f"Exported {kind.replace('-', ' ').title()}",
            "component": name, "permission": permission,
            "evidence": 'android:exported="true"', "assessment": assessment,
        })
    return sorted(findings, key=lambda x: (x["title"], x["component"]))
