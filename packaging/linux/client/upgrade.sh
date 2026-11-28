#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$script_dir/client-common.sh"

usage() {
  cat <<'EOF'
Usage: upgrade.sh <asl-client-linux-*.tar.gz> [--enable-user-service] [--no-start]
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi
if [[ $# -lt 1 ]]; then
  usage >&2
  exit 2
fi
artifact="$1"
shift
enable_service=0
start_service=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --enable-user-service)
      enable_service=1
      shift
      ;;
    --no-start)
      start_service=0
      shift
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

layout_file="$script_dir/install-layout.conf"
asl_client_load_layout "$layout_file"
[[ "$script_dir" == "$asl_tools_dir" ]] \
  || asl_client_die "Upgrade tooling is not running from the installed tools directory."
[[ -f "$artifact" && ! -L "$artifact" ]] \
  || asl_client_die "Upgrade artifact is not a regular file: $artifact"
artifact="$(realpath -- "$artifact")"
hash_file="$artifact.sha256"
if [[ -f "$hash_file" ]]; then
  (
    cd "$(dirname "$artifact")"
    sha256sum -c "$(basename "$hash_file")" >/dev/null
  )
fi

python3 "$script_dir/release_archive.py" verify "$artifact" >/dev/null
stage="$(mktemp -d)"
cleanup() {
  local status=$?
  trap - EXIT
  rm -rf -- "$stage"
  exit "$status"
}
trap cleanup EXIT
package_root="$(python3 "$script_dir/release_archive.py" extract "$artifact" "$stage")"

user_unit_dir="$(asl_client_user_unit_dir)"
user_unit="$user_unit_dir/asl-core.service"
service_was_active=0
if [[ -f "$user_unit" ]] && grep -Fqx "ExecStart=$asl_client_prefix/bin/asl-core-service" "$user_unit"; then
  enable_service=1
  if command -v systemctl >/dev/null 2>&1 \
    && systemctl --user is-active --quiet asl-core.service; then
    service_was_active=1
  fi
fi

args=(
  --upgrade
  --prefix "$asl_client_prefix"
  --asl-home "$asl_client_home"
  --skip-profile-init
)
if (( enable_service )); then
  args+=(--enable-user-service)
fi
if (( enable_service && (! start_service || ! service_was_active) )); then
  args+=(--no-start)
fi
bash "$package_root/install.sh" "${args[@]}"

if [[ ! -f "$user_unit" ]]; then
  printf 'Upgrade installed. Restart a directly launched Core before reconnecting clients.\n'
fi
