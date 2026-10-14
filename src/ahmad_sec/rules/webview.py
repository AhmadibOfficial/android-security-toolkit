def analyze_webview(apk):
    findings = []

    dex_strings = []

    try:
        for dex in apk.get_all_dex():
            dex_strings.extend(dex.get_strings())
    except Exception:
        return findings

    javascript_enabled = any(
        "setJavaScriptEnabled" in s
        for s in dex_strings
    )

    if javascript_enabled:
        findings.append({
            "id": "AST-SEC-004",
            "severity": "MEDIUM",
            "confidence": "MEDIUM",
            "title": "WebView JavaScript enabled",
            "cwe": "CWE-79",
            "evidence": "setJavaScriptEnabled",
            "assessment": (
                "WebView JavaScript is enabled; risk depends on "
                "the content loaded and the WebView's surrounding controls."
            ),
        })

    return findings
