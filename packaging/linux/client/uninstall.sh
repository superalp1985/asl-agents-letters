#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$script_dir/client-common.sh"

usage() {
  cat <<'EOF'
Usage: uninstall.sh [options]

Options:
  --prefix DIR       Installed prefix (default: loaded from this installer)
  --purge-config     Remove the generated prefix configuration
  --purge-data       Remove ASL_HOME after uninstalling the client
  -h, --help         Show this help
EOF
}

prefix=""
purge_config=0
purge_data=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      prefix="$2"
      shift 2
      ;;
    --purge-config)
      purge_config=1
      shift
      ;;
    --purge-data)
      purge_data=1
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

for required_command in grep readlink realpath rm rmdir; do
  command -v "$required_command" >/dev/null 2>&1 || {
    printf 'Required system command is missing: %s\n' "$required_command" >&2
    exit 1
  }
done

if [[ -z "$prefix" ]]; then
  case "$script_dir" in
    */libexec/asl)
      prefix="${script_dir%/libexec/asl}"
      ;;
    *)
      asl_client_die "Pass --prefix when running the package copy of uninstall.sh."
      ;;
  esac
fi
asl_client_validate_path "$prefix" 'Install prefix'
prefix="$(realpath -m -- "$prefix")"
layout_file="$prefix/lib/asl/install-layout.conf"
[[ -f "$layout_file" ]] || asl_client_die "No managed ASL client installation exists under $prefix"
asl_client_load_layout "$layout_file"
[[ "$asl_client_prefix" == "$prefix" ]] \
  || asl_client_die "Installed layout does not belong to $prefix"
asl_home="$asl_client_home"

user_unit_dir="$(asl_client_user_unit_dir)"
user_unit="$user_unit_dir/asl-core.service"
if [[ -f "$user_unit" ]] && grep -Fqx "ExecStart=$prefix/bin/asl-core-service" "$user_unit"; then
  if command -v systemctl >/dev/null 2>&1; then
    systemctl --user disable --now asl-core.service >/dev/null 2>&1 || true
    systemctl --user daemon-reload >/dev/null 2>&1 || true
  fi
  rm -f -- "$user_unit"
fi

for executable in asl asl-core asl-net asl-worker asl-extractor asl-ui; do
  path="$prefix/bin/$executable"
  if [[ -L "$path" ]] \
    && [[ "$(readlink -- "$path")" == "$asl_release_root/current/bin/$executable" ]]; then
    rm -f -- "$path"
  elif [[ -e "$path" || -L "$path" ]]; then
    printf 'Preserved unmanaged launcher: %s\n' "$path"
  fi
done
launch_path="$prefix/bin/asl-launch"
if [[ -L "$launch_path" && "$(readlink -- "$launch_path")" == "$asl_tools_dir/asl-launch" ]]; then
  rm -f -- "$launch_path"
elif [[ -e "$launch_path" || -L "$launch_path" ]]; then
  printf 'Preserved unmanaged launcher: %s\n' "$launch_path"
fi
service_launcher="$prefix/bin/asl-core-service"
if [[ -L "$service_launcher" && "$(readlink -- "$service_launcher")" == "$asl_tools_dir/asl-core-service" ]]; then
  rm -f -- "$service_launcher"
elif [[ -e "$service_launcher" || -L "$service_launcher" ]]; then
  printf 'Preserved unmanaged service launcher: %s\n' "$service_launcher"
fi

rm -f -- "$asl_desktop_dir/asl.desktop"
rm -f -- "$asl_icon_root/scalable/apps/asl.svg" "$asl_icon_root/256x256/apps/asl.png"
rm -f -- "$asl_service_dir/asl-core.service"
doc_dir="$prefix/share/doc/asl"
for document in README.md LICENSE THIRD-PARTY.txt sbom.cdx.json MPL-SOURCES.zip \
  BUILD-INFO.json APT-DEPENDENCIES.txt APT-PACKAGES.txt install-deps.sh; do
  rm -f -- "$doc_dir/$document"
done
rmdir -- "$doc_dir" 2>/dev/null || true
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database -q "$asl_desktop_dir" >/dev/null 2>&1 || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -q "$asl_icon_root" >/dev/null 2>&1 || true
fi

case "$asl_release_root" in
  "$prefix"/lib/asl/releases) ;;
  *) asl_client_die "Refusing unexpected release root: $asl_release_root" ;;
esac
case "$asl_tools_dir" in
  "$prefix"/libexec/asl) ;;
  *) asl_client_die "Refusing unexpected tools directory: $asl_tools_dir" ;;
esac
rm -rf -- "$asl_release_root" "$asl_tools_dir"
rm -f -- "$layout_file"

config_path="$prefix/etc/asl/asl.env"
if (( purge_config )); then
  rm -f -- "$config_path"
  rmdir -- "$prefix/etc/asl" "$prefix/etc" 2>/dev/null || true
else
  printf 'Preserved configuration: %s\n' "$config_path"
fi

if (( purge_data )); then
  case "$asl_home" in
    /|"$HOME"|"$prefix")
      asl_client_die "Refusing to purge unsafe ASL_HOME: $asl_home"
      ;;
  esac
  rm -rf -- "$asl_home"
  printf 'Removed ASL_HOME: %s\n' "$asl_home"
else
  printf 'Preserved ASL_HOME data: %s\n' "$asl_home"
fi

rmdir -- "$prefix/bin" "$prefix/lib/asl" "$prefix/lib" "$prefix/share/applications" 2>/dev/null || true
printf 'Uninstalled ASL client from %s\n' "$prefix"
