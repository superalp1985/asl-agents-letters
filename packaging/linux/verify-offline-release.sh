#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

if [[ $# -ne 5 ]]; then
  printf 'Usage: %s <artifact.tar.gz> <signature> <public-key.pem> <sha256-file> <trusted-key-sha256>\n' "$0" >&2
  exit 2
fi

artifact="$1"
signature="$2"
public_key="$3"
hash_file="$4"
trusted_key_hash="$5"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if ! command -v python3 >/dev/null 2>&1; then
  printf 'Python 3 is required for safe archive inspection.\n' >&2
  exit 1
fi

bash "$script_dir/verify-release.sh" \
  "$artifact" \
  "$signature" \
  "$public_key" \
  ASL-LINUX-INFRA-RELEASE-v1 \
  "$hash_file" \
  "$trusted_key_hash"

python3 "$script_dir/release_archive.py" verify "$artifact"
printf 'Offline Linux release verification passed.\n'
