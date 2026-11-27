#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 4 || $# -gt 5 ]]; then
  printf 'Usage: %s <artifact> <signature> <public-key.pem> <domain> [expected-sha256-file]\n' "$0" >&2
  exit 2
fi

artifact="$1"
signature="$2"
public_key="$3"
domain="$4"
hash_file="${5:-}"

for path in "$artifact" "$signature" "$public_key"; do
  if [[ ! -f "$path" ]]; then
    printf 'Missing release input: %s\n' "$path" >&2
    exit 1
  fi
done
if ! command -v openssl >/dev/null 2>&1; then
  printf 'OpenSSL 3 is required.\n' >&2
  exit 1
fi
if [[ -n "$hash_file" ]]; then
  (
    cd "$(dirname "$hash_file")"
    sha256sum -c "$(basename "$hash_file")"
  )
fi

temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
printf '%s\0' "$domain" > "$temporary/message.bin"
cat "$artifact" >> "$temporary/message.bin"
openssl pkeyutl \
  -verify \
  -pubin \
  -inkey "$public_key" \
  -rawin \
  -in "$temporary/message.bin" \
  -sigfile "$signature"
