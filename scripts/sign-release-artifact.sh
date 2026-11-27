#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 4 ]]; then
  printf 'Usage: %s <private-key.pem> <artifact> [domain] [output-directory]\n' "$0" >&2
  exit 2
fi

private_key="$1"
artifact="$2"
domain="${3:-ASL-RELEASE-v1}"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ ! -f "$private_key" || ! -f "$artifact" ]]; then
  printf 'Private key and artifact must be existing files.\n' >&2
  exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
  printf 'OpenSSL 3 is required.\n' >&2
  exit 1
fi

private_key="$(realpath "$private_key")"
artifact="$(realpath "$artifact")"
case "$private_key" in
  "$repo"/*)
    printf 'Refusing to use a private key stored inside the repository.\n' >&2
    exit 1
    ;;
esac

output_dir="${4:-$(dirname "$artifact")}"
mkdir -p "$output_dir"
output_dir="$(realpath "$output_dir")"
stem="$(basename "$artifact")"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT

printf '%s\0' "$domain" > "$temporary/message.bin"
cat "$artifact" >> "$temporary/message.bin"

openssl pkeyutl \
  -sign \
  -rawin \
  -inkey "$private_key" \
  -in "$temporary/message.bin" \
  -out "$temporary/signature.bin"
openssl pkey \
  -in "$private_key" \
  -pubout \
  -out "$temporary/release-key.pem"
openssl pkey \
  -in "$private_key" \
  -pubout \
  -outform DER \
  -out "$temporary/release-key.der"

openssl pkeyutl \
  -verify \
  -pubin \
  -inkey "$temporary/release-key.pem" \
  -rawin \
  -in "$temporary/message.bin" \
  -sigfile "$temporary/signature.bin" >/dev/null

install -m 0644 "$temporary/signature.bin" "$output_dir/$stem.sig"
install -m 0644 "$temporary/release-key.pem" "$output_dir/$stem.release-key.pem"
tail -c 32 "$temporary/release-key.der" > "$output_dir/$stem.release-key.ed25519"
chmod 0644 "$output_dir/$stem.release-key.ed25519"
hash_value="$(sha256sum "$artifact" | awk '{print $1}')"
printf '%s  %s\n' "$hash_value" "$stem" > "$output_dir/$stem.sha256"

printf '%s\n' "$output_dir/$stem.sig"
printf '%s\n' "$output_dir/$stem.release-key.pem"
printf '%s\n' "$output_dir/$stem.release-key.ed25519"
printf '%s\n' "$output_dir/$stem.sha256"
