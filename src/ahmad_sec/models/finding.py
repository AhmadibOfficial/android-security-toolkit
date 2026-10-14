from dataclasses import dataclass


@dataclass
class Finding:
    id: str
    severity: str
    confidence: str
    title: str
    cwe: str | None = None
    component: str | None = None
    evidence: str | None = None
    assessment: str | None = None
    file: str | None = None
