#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 022

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
packages_file="$repo/packaging/linux/client/apt-packages.txt"
output_dir=""
seed_cache=""
offline=0

usage() {
  cat <<'EOF'
Usage: prepare-linux-client-deps.sh --output-dir DIR [options]

Create an Ubuntu-version-specific dependency bundle for the ASL Linux client.
The output contains every recursively resolved .deb package needed by the
declared desktop runtime packages, plus target metadata and a SHA-256 manifest.

Options:
  --output-dir DIR    New output directory for the dependency bundle
  --seed-cache DIR    Copy matching .deb files from an existing APT archive cache
  --offline           Never download; fail unless the seeded cache is complete
  -h, --help          Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      output_dir="$2"
      shift 2
      ;;
    --seed-cache)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      seed_cache="$2"
      shift 2
      ;;
    --offline)
      offline=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

[[ -n "$output_dir" ]] || { usage >&2; exit 2; }
[[ "$output_dir" == /* && "$output_dir" != "/" ]] \
  || { printf 'Output directory must be an absolute non-root path.\n' >&2; exit 2; }
[[ ! -e "$output_dir" && ! -L "$output_dir" ]] \
  || { printf 'Refusing to overwrite an existing dependency output: %s\n' "$output_dir" >&2; exit 1; }

for command in apt-get dpkg dpkg-deb gzip sha256sum find sort awk sed install python3; do
  command -v "$command" >/dev/null 2>&1 \
    || { printf 'Required build command is missing: %s\n' "$command" >&2; exit 1; }
done
[[ -f /etc/os-release ]] || { printf '/etc/os-release is missing.\n' >&2; exit 1; }
# shellcheck disable=SC1091
. /etc/os-release
[[ "${ID:-}" == "ubuntu" ]] \
  || { printf 'The client dependency bundle must be prepared on Ubuntu.\n' >&2; exit 1; }
[[ "${VERSION_ID:-}" =~ ^[0-9]{2}\.[0-9]{2}$ ]] \
  || { printf 'Unsupported Ubuntu VERSION_ID: %s\n' "${VERSION_ID:-}" >&2; exit 1; }
host_arch="$(dpkg --print-architecture)"
case "$host_arch" in
  amd64|arm64) ;;
  *) printf 'Unsupported Ubuntu architecture: %s\n' "$host_arch" >&2; exit 1 ;;
esac

mapfile -t packages < <(awk 'NF && $1 !~ /^#/ { print $1 }' "$packages_file")
[[ "${#packages[@]}" -gt 0 ]] \
  || { printf 'The APT package list is empty.\n' >&2; exit 1; }

parent="$(dirname "$output_dir")"
install -d -m 0755 "$parent"
stage="$(mktemp -d "$parent/.asl-client-deps.XXXXXX")"
cache="$stage/cache"
print_cache="$stage/print-cache"
empty_status="$stage/status"
log="$stage/apt.log"
mkdir -p "$cache" "$print_cache"
: > "$empty_status"

cleanup() {
  local status=$?
  trap - EXIT
  rm -rf -- "$stage"
  exit "$status"
}
trap cleanup EXIT

if (( ! offline )); then
  (
    cd "$stage"
    apt-get update
  ) >"$log" 2>&1
fi

print_args=(
  -o "Dir::State::status=$empty_status"
  -o "Dir::Cache::archives=$print_cache"
  --print-uris
  --no-install-recommends
  --yes
  install
)
uri_output="$(
  (
    cd "$stage"
    apt-get "${print_args[@]}" "${packages[@]}" 2>>"$log"
  ) | sed -n "s/^'\([^']*\.deb\)'.*/\1/p"
)"
dependency_uris=()
if [[ -n "$uri_output" ]]; then
  mapfile -t dependency_uris <<<"$uri_output"
fi
[[ "${#dependency_uris[@]}" -gt 0 ]] \
  || { printf 'APT resolved no dependency .deb files.\n' >&2; cat "$log" >&2; exit 1; }
logical_deb_name() {
  python3 -c 'import sys, urllib.parse; print(urllib.parse.unquote(sys.argv[1]))' "$1"
}
deb_file_key() {
  local deb="$1"
  local package version
  package="$(dpkg-deb -f "$deb" Package)"
  version="$(dpkg-deb -f "$deb" Version)"
  printf '%s|%s\n' "$package" "${version#*:}"
}
deb_uri_key() {
  local base logical package remainder version
  base="$1"
  logical="$(logical_deb_name "$base")"
  package="${logical%%_*}"
  remainder="${logical#*_}"
  version="${remainder%_*}"
  printf '%s|%s\n' "$package" "${version#*:}"
}
if [[ -n "$seed_cache" ]]; then
  [[ -d "$seed_cache" && ! -L "$seed_cache" ]] \
    || { printf 'Seed cache is not a real directory: %s\n' "$seed_cache" >&2; exit 1; }
  declare -A seed_files=()
  while IFS= read -r -d '' candidate; do
    seed_files["$(deb_file_key "$candidate")"]="$candidate"
  done < <(find "$seed_cache" -maxdepth 1 -type f -name '*.deb' -print0)
  for uri in "${dependency_uris[@]}"; do
    key="$(deb_uri_key "${uri##*/}")"
    source_deb="${seed_files[$key]:-}"
    if [[ -n "$source_deb" ]]; then
      cp -p -- "$source_deb" "$cache/$(basename "$source_deb")"
    fi
  done
fi

if (( ! offline )); then
  apt_args=(
    -o "Dir::State::status=$empty_status"
    -o "Dir::Cache::archives=$cache"
    --download-only
    --no-install-recommends
    --yes
    install
  )
  if ! (
    cd "$stage"
    apt-get "${apt_args[@]}" "${packages[@]}"
  ) >>"$log" 2>&1; then
    cat "$log" >&2
    printf 'APT dependency download did not complete.\n' >&2
    exit 1
  fi
  find "$cache" -maxdepth 1 -type f \( -name 'lock' -o -name 'partial' \) -delete
fi
missing=()
declare -A downloaded_files=()
while IFS= read -r -d '' candidate; do
  downloaded_files["$(deb_file_key "$candidate")"]="$candidate"
done < <(find "$cache" -maxdepth 1 -type f -name '*.deb' -print0)
for uri in "${dependency_uris[@]}"; do
  key="$(deb_uri_key "${uri##*/}")"
  deb="${downloaded_files[$key]:-}"
  if [[ -z "$deb" ]]; then
    missing+=("${key%%|*}_${key#*|}")
    continue
  fi
  dpkg-deb --info "$deb" >/dev/null
  install -m 0644 "$deb" "$stage/$(basename "$deb")"
done
if [[ "${#missing[@]}" -gt 0 ]]; then
  printf 'Required dependency .deb files are missing:\n' >&2
  printf '  %s\n' "${missing[@]}" >&2
  exit 1
fi

cat > "$stage/TARGET-UBUNTU.txt" <<EOF
ID=ubuntu
VERSION_ID=$VERSION_ID
VERSION_CODENAME=${VERSION_CODENAME:-unknown}
ARCH=$host_arch
EOF
{
  printf '# Generated from packaging/linux/client/apt-packages.txt\n'
  printf '%s\n' "${packages[@]}"
} > "$stage/APT-PACKAGES.txt"

(
  cd "$stage"
  find . -maxdepth 1 -type f -name '*.deb' -printf '%f\n' \
    | sort \
    | while IFS= read -r deb; do sha256sum "$deb"; done \
    > DEB-SHA256SUMS
)

rm -rf -- "$cache" "$print_cache" "$empty_status" "$log"
mv -- "$stage" "$output_dir"
trap - EXIT
printf '%s\n' "$output_dir"
