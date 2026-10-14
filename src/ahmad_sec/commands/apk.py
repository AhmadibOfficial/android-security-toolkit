import typer
from pathlib import Path
from zipfile import BadZipFile
from rich.console import Console
from rich.table import Table
from ahmad_sec.analyzers.apk_analyzer import APKAnalyzer
from ahmad_sec.analyzers.secret_analyzer import scan_apk
from ahmad_sec.rules.manifest import analyze_manifest
from ahmad_sec.rules.components import analyze_components
from ahmad_sec.rules.network import analyze_network
from ahmad_sec.core.finding import normalize_finding

app = typer.Typer(help="Android APK security analysis commands")
console = Console()


@app.command()
def scan(target: Path = typer.Argument(..., help="Path to a local APK")):
    """Run static APK reconnaissance and evidence-led security checks."""
    if not target.is_file() or target.suffix.lower() != ".apk":
        console.print("Invalid APK file path.", markup=False)
        raise typer.Exit(code=2)

    try:
        analyzer = APKAnalyzer(str(target))
        result = analyzer.analyze()
        raw_findings = (
            analyze_manifest(analyzer.apk)
            + analyze_components(analyzer.apk)
            + analyze_network(analyzer.apk)
            + scan_apk(str(target))
        )
    except (OSError, ValueError, BadZipFile) as exc:
        console.print(f"APK analysis failed: {type(exc).__name__}", markup=False)
        raise typer.Exit(code=1) from exc

    findings = []
    for raw in raw_findings:
        item = normalize_finding(raw)
        for field in ("file", "permission"):
            if raw.get(field) is not None:
                item[field] = raw[field]
        findings.append(item)
    findings.sort(key=lambda item: (-item["risk_score"], item["title"], item.get("component") or ""))

    console.print("AHMAD-IB ANDROID SECURITY LAB", style="bold cyan")
    table = Table(title="APK Metadata")
    table.add_column("Property")
    table.add_column("Value")
    for key, value in result["metadata"].items():
        table.add_row(str(key), str(value))
    console.print(table)
    console.print("Security Findings", style="bold")
    if not findings:
        console.print("No findings from the currently enabled checks.", markup=False)
    for finding in findings:
        summary = f"[{finding['severity']}] {finding['title']} | Confidence: {finding['confidence']} | Risk: {finding['risk_score']}"
        console.print(summary, markup=False)
        for key in ("component", "permission", "file", "cwe", "evidence", "assessment"):
            value = finding.get(key)
            if value is not None:
                console.print(f"  {key.capitalize()}: {value}", markup=False)
