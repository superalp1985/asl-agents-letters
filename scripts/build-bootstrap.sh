#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

if [[ $# -ne 1 ]]; then
  printf 'Usage: %s <new-output-directory>\n' "$0" >&2
  exit 2
fi
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output="$1"
if [[ "$output" != /* || -e "$output" ]]; then
  printf 'Output must be a new absolute path.\n' >&2
  exit 2
fi
if [[ "$(uname -s)" != "Linux" ]]; then
  printf 'Build the Linux bootstrap on Linux.\n' >&2
  exit 1
fi
if [[ "$(uname -m)" != "x86_64" ]]; then
  printf 'This build entry currently targets x86_64 Linux.\n' >&2
  exit 1
fi
command -v python3 >/dev/null
python3 -c 'import cryptography, PyInstaller' >/dev/null
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
python3 -m PyInstaller \
  --noconfirm \
  --clean \
  --onefile \
  --name asl-bootstrap-linux-x86_64 \
  --distpath "$work" \
  --workpath "$work/build" \
  --specpath "$work" \
  --paths "$repo" \
  "$repo/bootstrap/asl_bootstrap.py"
destination="$output/asl-bootstrap-linux-x86_64"
mkdir -p "$output"
install -m 0755 "$work/asl-bootstrap-linux-x86_64" "$destination"
printf '%s\n' "$destination"
