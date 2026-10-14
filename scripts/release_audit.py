#!/usr/bin/env python3
"""Non-destructive release hygiene audit. No APK parsing or network calls."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def git(*args):
    return subprocess.run(['git', *args], cwd=ROOT, text=True, capture_output=True, check=True).stdout


def bad_path(path):
    parts = path.replace('\\', '/').split('/')
    return (
        path.lower().endswith(('.apk', '.aab', '.apks', '.pyc', '.p12', '.pfx', '.keystore', '.jks'))
        or '__pycache__' in parts
        or '.venv' in parts
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=['development', 'release'], default='development')
    args = parser.parse_args()
    failures = []
    for relative in ('README.md', 'SECURITY.md', 'LICENSE', '.github/workflows/ci.yml'):
        path = ROOT / relative
        if not path.is_file() or path.stat().st_size == 0:
            failures.append(f'Missing or empty: {relative}')

    tracked = git('ls-files').splitlines()
    flagged = [p for p in tracked if bad_path(p)]
    if flagged:
        failures.append('Files tracked in current Git tree: ' + ', '.join(flagged[:10]))

    if args.mode == 'release':
        # Git's reachable objects retain files deleted in later commits.
        seen = git('rev-list', '--objects', '--all').splitlines()
        historical = sorted({
            line.split(' ', 1)[1] for line in seen if ' ' in line and bad_path(line.split(' ', 1)[1])
        })
        if historical:
            failures.append('Forbidden files in reachable Git history: ' + ', '.join(historical[:10]))
        if git('status', '--porcelain').strip():
            failures.append('Working tree is not clean (commit or remove untracked files before release)')

    if failures:
        for issue in failures:
            print('FAIL:', issue)
        return 1
    print('PASS:', 'release' if args.mode == 'release' else 'development', 'hygiene checks')
    if args.mode == 'development':
        print('Note: release mode additionally checks all reachable Git history and clean status.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
