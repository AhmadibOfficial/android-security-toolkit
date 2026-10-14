from ahmad_sec.analyzers.content_analyzer import extract_text
from ahmad_sec.rules.secrets import scan_text


def scan_apk(apk_path):
    findings = []

    for filename, text in extract_text(apk_path):
        for finding in scan_text(text):
            finding["file"] = filename
            findings.append(finding)

    return findings
