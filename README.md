# AHMAD-IB Android Security Toolkit

An experimental open-source **Android security assessment CLI** focused on reproducible evidence and practical security impact.

> Not every vulnerability matters. Fix the ones that do.

## Install

Requires Python 3.11 or later.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
ahmad-sec --help
```

## Authorized APK reconnaissance

```bash
ahmad-sec apk scan /path/to/your/authorized.apk
```

## Tests and release audit

```bash
python -m pytest -q
python scripts/release_audit.py --mode development
```

## Limits

This tool currently reports **observations and potential weaknesses**. Exported components and configuration flags alone do not prove exploitation. Secret detection does not cover all APK code/data formats. See `docs/RESEARCH_PROCESS.md` and `docs/PUBLICATION_CHECKLIST.md`.

## Responsible use

Scan only applications you own or are authorized to assess. Never commit third-party APK files or sensitive evidence. Follow the repository `SECURITY.md` for private vulnerability disclosure.
