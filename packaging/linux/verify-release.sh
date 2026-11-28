#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

if [[ $# -lt 4 || $# -gt 6 ]]; then
  printf 'Usage: %s <artifact> <signature> <public-key.pem> <domain> [expected-sha256-file] [trusted-key-sha256]\n' "$0" >&2
  exit 2
fi

artifact="$1"
signature="$2"
public_key="$3"
domain="$4"
hash_file="${5:-}"
trusted_key_hash="${6:-}"
if [[ ! "$domain" =~ ^[A-Z0-9._-]{1,64}$ ]]; then
  printf 'The release signature domain is invalid.\n' >&2
  exit 2
fi
if [[ ! "$(basename "$artifact")" =~ ^[A-Za-z0-9._+-]+$ ]]; then
  printf 'Artifact filename contains unsupported characters.\n' >&2
  exit 1
fi

for path in "$artifact" "$signature" "$public_key"; do
  if [[ ! -f "$path" ]]; then
    printf 'Missing release input: %s\n' "$path" >&2
    exit 1
  fi
done
if [[ "$(wc -c < "$signature" | tr -d ' ')" -ne 64 ]]; then
  printf 'Ed25519 release signature must contain exactly 64 bytes.\n' >&2
  exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
  printf 'OpenSSL 3 is required.\n' >&2
  exit 1
fi
if [[ -n "$trusted_key_hash" ]]; then
  if [[ ! "$trusted_key_hash" =~ ^([[:xdigit:]]{64})$ ]]; then
    printf 'Trusted public-key SHA-256 must be 64 hexadecimal characters.\n' >&2
    exit 2
  fi
  temporary_key="$(mktemp)"
  trap 'rm -f "$temporary_key"' EXIT
  openssl pkey -pubin -in "$public_key" -outform DER -out "$temporary_key"
  if [[ "$(wc -c < "$temporary_key" | tr -d ' ')" -ne 44 ]]; then
    printf 'The supplied public key is not an Ed25519 SubjectPublicKeyInfo key.\n' >&2
    exit 1
  fi
  der_prefix="$(head -c 12 "$temporary_key" | od -An -tx1 | tr -d ' \n')"
  if [[ "$der_prefix" != "302a300506032b6570032100" ]]; then
    printf 'The supplied public key is not Ed25519.\n' >&2
    exit 1
  fi
  actual_key_hash="$(tail -c 32 "$temporary_key" | sha256sum | awk '{print $1}')"
  expected_key_hash="${trusted_key_hash,,}"
  if [[ "$actual_key_hash" != "$expected_key_hash" ]]; then
    printf 'Public-key fingerprint mismatch; authenticate the key out of band.\n' >&2
    exit 1
  fi
  rm -f "$temporary_key"
  trap - EXIT
fi
if [[ -n "$hash_file" ]]; then
  if [[ ! -f "$hash_file" ]]; then
    printf 'Missing expected SHA-256 file: %s\n' "$hash_file" >&2
    exit 1
  fi
  mapfile -t hash_lines < "$hash_file"
  if [[ "${#hash_lines[@]}" -ne 1 ]] \
    || [[ ! "${hash_lines[0]}" =~ ^([[:xdigit:]]{64})\ \ ([A-Za-z0-9._+-]+)$ ]]; then
    printf 'Expected a single SHA-256 entry for the artifact.\n' >&2
    exit 1
  fi
  expected_hash="${BASH_REMATCH[1],,}"
  expected_name="${BASH_REMATCH[2]}"
  if [[ "$expected_name" != "$(basename "$artifact")" ]]; then
    printf 'SHA-256 entry names a different artifact.\n' >&2
    exit 1
  fi
  actual_hash="$(sha256sum -- "$artifact" | awk '{print $1}')"
  if [[ "$actual_hash" != "$expected_hash" ]]; then
    printf 'Artifact SHA-256 mismatch.\n' >&2
    exit 1
  fi
fi

temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
printf '%s\0' "$domain" > "$temporary/message.bin"
cat -- "$artifact" >> "$temporary/message.bin"
openssl pkeyutl \
  -verify \
  -pubin \
  -inkey "$public_key" \
  -rawin \
  -in "$temporary/message.bin" \
  -sigfile "$signature"
