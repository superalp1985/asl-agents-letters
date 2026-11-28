#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

if [[ $# -lt 2 || $# -gt 4 ]]; then
  printf 'Usage: %s <private-key.pem> <artifact> [domain] [output-directory]\n' "$0" >&2
  exit 2
fi

private_key="$1"
artifact="$2"
domain="${3:-ASL-RELEASE-v1}"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ ! "$domain" =~ ^[A-Z0-9._-]{1,64}$ ]]; then
  printf 'The release signature domain must be 1-64 uppercase portable characters.\n' >&2
  exit 2
fi

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
if [[ ! "$stem" =~ ^[A-Za-z0-9._+-]+$ ]]; then
  printf 'Artifact filename contains unsupported characters.\n' >&2
  exit 1
fi
for suffix in sig release-key.pem release-key.ed25519 sha256; do
  if [[ -e "$output_dir/$stem.$suffix" ]]; then
    printf 'Refusing to overwrite existing release output: %s\n' "$output_dir/$stem.$suffix" >&2
    exit 1
  fi
done
temporary="$(mktemp -d)"
published=0
finish_signing() {
  local status=$?
  trap - EXIT
  rm -rf -- "$temporary"
  if (( ! published )); then
    rm -f -- \
      "$output_dir/$stem.sig" \
      "$output_dir/$stem.release-key.pem" \
      "$output_dir/$stem.release-key.ed25519" \
      "$output_dir/$stem.sha256"
  fi
  exit "$status"
}
trap finish_signing EXIT

printf '%s\0' "$domain" > "$temporary/message.bin"
cat -- "$artifact" >> "$temporary/message.bin"

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
if [[ "$(wc -c < "$temporary/release-key.der" | tr -d ' ')" -ne 44 ]] \
  || [[ "$(head -c 12 "$temporary/release-key.der" | od -An -tx1 | tr -d ' \n')" != "302a300506032b6570032100" ]]; then
  printf 'The supplied release private key must be Ed25519.\n' >&2
  exit 1
fi

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
key_fingerprint="$(sha256sum "$output_dir/$stem.release-key.ed25519" | awk '{print $1}')"
published=1

printf '%s\n' "$output_dir/$stem.sig"
printf '%s\n' "$output_dir/$stem.release-key.pem"
printf '%s\n' "$output_dir/$stem.release-key.ed25519"
printf '%s\n' "$output_dir/$stem.sha256"
printf 'Public-key SHA-256: %s\n' "$key_fingerprint"
