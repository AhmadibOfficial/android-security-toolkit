#!/usr/bin/env bash
# Create a separate sanitized clone. Do not rewrite the working source repository.
set -euo pipefail
source_repo="$(git rev-parse --show-toplevel)"
output="${1:-${source_repo}-public-clean}"
if [[ -n "$(git status --porcelain)" ]]; then
  echo 'STOP: Commit or deliberately exclude all work (including untracked files) before cloning.' >&2
  exit 1
fi
if ! git filter-repo --version >/dev/null 2>&1; then
  echo 'Install git-filter-repo (e.g. sudo apt install git-filter-repo) before continuing.' >&2
  exit 1
fi
if [[ -e "$output" ]]; then
  echo "STOP: Output already exists: $output" >&2
  exit 1
fi
git clone --no-local "$source_repo" "$output"
(
  cd "$output"
  git filter-repo --force --invert-paths \
    --path examples/apks/app1739161.apk \
    --path-glob '*.apk' \
    --path-glob '*.aab' \
    --path-glob '*.apks' \
    --path-glob '*.pyc' \
    --path-regex '(^|/)__pycache__(/|$)'
  python3 scripts/release_audit.py --mode release
)
printf '\nSanitized local clone: %s\n' "$output"
printf 'Inspect the full diff and commit history before creating any public GitHub remote.\n'
