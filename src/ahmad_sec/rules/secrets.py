import hashlib
import re

PATTERNS = {
    "AWS Access Key": r"\bAKIA[0-9A-Z]{16}\b",
    "GitHub Token": r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b",
    "JWT": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    "Google API Key": r"\bAIza[0-9A-Za-z_-]{35}\b",
}


def scan_text(text: str):
    """Return masked, unverified secret candidates: never print raw credentials."""
    findings = []
    for name, pattern in PATTERNS.items():
        for match in re.finditer(pattern, text):
            candidate = match.group(0)
            masked = candidate[:4] + "..." + candidate[-4:]
            findings.append({
                "id": "AST-SEC-005", "severity": "LOW", "confidence": "LOW",
                "title": f"Potential {name}", "evidence": masked,
                "assessment": "Unverified pattern match. Validate securely before assigning risk.",
                "fingerprint": hashlib.sha256(candidate.encode("utf-8")).hexdigest()[:12],
            })
    return findings
