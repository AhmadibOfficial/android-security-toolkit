# AHMAD-IB Android Security Toolkit

A security assessment workbench for Android applications, combining
reproducible APK reconnaissance, privacy-conscious evidence review and a local
graphical workspace.

> Not every vulnerability matters. Fix the ones that do.

## Install

Requires Python 3.11 or later.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
ahmad-sec --help
```

## Scan an authorized APK

```bash
ahmad-sec apk scan /path/to/your/authorized.apk --json-out evidence.json
```

The CLI reports observations and potential weaknesses with evidence; it does
not automatically prove exploitability.

## Open the graphical workspace

```bash
ahmad-sec workspace
```

Open `http://127.0.0.1:8765/` if a browser does not open automatically. Use
the **Import evidence JSON** control to select the report just created.

The workspace displays real reported metrics, APK identity and metadata,
an interactive component/observation association graph, severity filters,
searchable findings, and a detailed evidence inspector. The interface adapts
to desktop and mobile browser widths, but the Python CLI must run on your
computer.

The workspace serves only local HTML/CSS/JavaScript. The browser reads the
JSON file locally; the server never receives your report. The workspace does
not run scans from the browser or remotely connect to devices.

Alternative port without automatically opening a browser:

```bash
ahmad-sec workspace --port 8877 --no-browser
```

## Tests and release audit

```bash
python -m pytest -q
python scripts/release_audit.py --mode development
```

## Engineering roadmap

See [Security Workspace Architecture](docs/SECURITY_WORKSPACE.md) for the
planned static analysis, runtime/mobile assessment, reporting, attack-surface
mapping, evidence and workflow architecture. Planned capabilities are
distinct from features currently implemented.

## Important limitations

The current scanner reports configuration and string-pattern observations,
not proof that a target is exploitable. Selected UTF-8 file matching cannot
prove absence of secrets in code, native libraries or all APK resources.
See [Research Process](docs/RESEARCH_PROCESS.md) and
[Publication Checklist](docs/PUBLICATION_CHECKLIST.md).

## Responsible use

Analyze only applications you own or are explicitly authorized to assess.
Never commit third-party APK files, credentials or sensitive evidence.
Follow [SECURITY.md](SECURITY.md) for private vulnerability disclosure.
