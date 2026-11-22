import typer
from pathlib import Path
from zipfile import BadZipFile
from rich.console import Console
from rich.table import Table
from ahmad_sec.analyzers.apk_analyzer import APKAnalyzer
from ahmad_sec.analyzers.attack_surface import build_surface_map
from ahmad_sec.analyzers.secret_analyzer import scan_apk
from ahmad_sec.rules.manifest import analyze_manifest
from ahmad_sec.rules.components import analyze_components
from ahmad_sec.rules.network import analyze_network
from ahmad_sec.core.finding import normalize_finding
from ahmad_sec.reporting.evidence import build_evidence_report, write_evidence_report

app = typer.Typer(help="Android APK security analysis commands")
console = Console()


@app.command()
def scan(
    target: Path = typer.Argument(..., help="Path to a local APK"),
    json_out: Path | None = typer.Option(None, "--json-out", help="Write redacted JSON evidence (new file only)"),
):
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

    if json_out is not None:
        report = build_evidence_report(result["metadata"], findings)
        report["surface"] = build_surface_map(
            analyzer.apk.get_android_manifest_xml(),
            package_name=analyzer.apk.get_package(),
            target_sdk=analyzer.apk.get_target_sdk_version(),
        )
        try:
            write_evidence_report(json_out, report)
        except (OSError, ValueError) as exc:
            console.print(f"Evidence export failed: {type(exc).__name__}", markup=False)
            raise typer.Exit(code=2) from exc
        console.print(f"Evidence JSON saved: {json_out}", markup=False)

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


@app.command("surface")
def surface(
    target: Path = typer.Argument(..., help="Path to your authorized local APK"),
    json_out: Path | None = typer.Option(
        None, "--json-out", help="Export a local machine-readable manifest attack-surface graph"
    ),
):
    """Inventory Android entry points, intent filters, deep links and permissions."""
    if not target.is_file() or target.suffix.lower() != ".apk":
        console.print("Invalid APK file path.", markup=False)
        raise typer.Exit(code=2)
    try:
        analyzer = APKAnalyzer(str(target))
        metadata = analyzer.analyze()["metadata"]
        graph = build_surface_map(
            analyzer.apk.get_android_manifest_xml(),
            package_name=analyzer.apk.get_package(),
            target_sdk=analyzer.apk.get_target_sdk_version(),
        )
    except (OSError, ValueError, BadZipFile) as exc:
        console.print(f"Surface analysis failed: {type(exc).__name__}", markup=False)
        raise typer.Exit(code=1) from exc

    console.print("MANIFEST ATTACK SURFACE | DECLARATIONS, NOT EXPLOITS", style="bold cyan")
    console.print(
        f"Components: {graph['summary']['components']} | "
        f"Exported and enabled: {graph['summary']['explicitly_exported_enabled']} | "
        f"Deep-link handlers: {graph['summary']['deep_link_handlers']} | "
        f"Unresolved export states: {graph['summary']['unknown_export_state']}",
        markup=False,
    )
    table = Table(title="Android application entry points")
    table.add_column("Kind")
    table.add_column("Name")
    table.add_column("Exported")
    table.add_column("Enabled")
    table.add_column("Permission / filter")
    for item in graph["components"]:
        permission = item["permission"] or item["read_permission"] or item["write_permission"] or "—"
        if item["filters"]:
            permission += f" ({len(item['filters'])} intent filters)"
        table.add_row(
            item["kind"], item["name"], str(item["exported"]),
            str(item["enabled"]), permission,
        )
    console.print(table)
    if graph["truncated"]:
        console.print("NOTE: Inventory limit reached; output is incomplete.", markup=False)
    if json_out is not None:
        report = build_evidence_report(metadata, [])
        report["surface"] = graph
        try:
            write_evidence_report(json_out, report)
        except (OSError, ValueError) as exc:
            console.print(f"Surface export failed: {type(exc).__name__}", markup=False)
            raise typer.Exit(code=2) from exc
        console.print(f"Surface JSON saved: {json_out}", markup=False)
