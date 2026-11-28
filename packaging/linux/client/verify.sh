#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'EOF'
Usage: verify.sh [asl-client-linux-*.tar.gz | asl-client_*.deb]

With no argument, verify the package directory containing this script.
An adjacent .sha256 sidecar is checked automatically when present.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi
if [[ $# -gt 1 ]]; then
  usage >&2
  exit 2
fi
if [[ $# -eq 0 ]]; then
  [[ -f "$script_dir/SHA256SUMS" ]] \
    || { printf 'This directory is not an ASL client package.\n' >&2; exit 1; }
  (
    cd "$script_dir"
    sha256sum -c SHA256SUMS
  )
  printf 'Verified ASL client package directory.\n'
  exit 0
fi

artifact="$1"
[[ -f "$artifact" && ! -L "$artifact" ]] \
  || { printf 'Artifact is not a regular file: %s\n' "$artifact" >&2; exit 1; }
hash_file="$artifact.sha256"
if [[ -f "$hash_file" ]]; then
  (
    cd "$(dirname "$artifact")"
    sha256sum -c "$(basename "$hash_file")" >/dev/null
  )
fi

case "$artifact" in
  *.tar.gz)
    command -v python3 >/dev/null 2>&1 || {
      printf 'python3 is required to inspect the tar.gz package.\n' >&2
      exit 1
    }
    python3 "$script_dir/release_archive.py" verify "$artifact"
    ;;
  *.deb)
    command -v dpkg-deb >/dev/null 2>&1 || {
      printf 'dpkg-deb is required to inspect the deb package.\n' >&2
      exit 1
    }
    command -v sha256sum >/dev/null 2>&1 || {
      printf 'sha256sum is required to inspect the deb package.\n' >&2
      exit 1
    }
    dpkg-deb --info "$artifact" >/dev/null
    contents="$(dpkg-deb --contents "$artifact")"
    for required in \
      ./opt/asl/bin/asl-core ./opt/asl/bin/asl-ui ./opt/asl/bin/asl-core-service \
      ./usr/share/doc/asl/APT-PACKAGES.txt \
      ./usr/share/applications/asl.desktop \
      ./usr/share/icons/hicolor/scalable/apps/asl.svg \
      ./usr/lib/systemd/user/asl-core.service; do
      grep -Fq -- "$required" <<<"$contents" \
        || { printf 'Deb is missing required path: %s\n' "$required" >&2; exit 1; }
    done
    deb_check="$(mktemp -d)"
    trap 'rm -rf "$deb_check"' EXIT
    dpkg-deb --extract "$artifact" "$deb_check"
    [[ -f "$deb_check/usr/share/doc/asl/SHA256SUMS" ]] \
      || { printf 'Deb is missing its installed-file SHA256SUMS.\n' >&2; exit 1; }
    (
      cd "$deb_check"
      sha256sum -c usr/share/doc/asl/SHA256SUMS
    )
    printf 'Verified ASL client deb structure: %s\n' "$artifact"
    ;;
  *)
    printf 'Unsupported artifact type: %s\n' "$artifact" >&2
    exit 2
    ;;
esac
