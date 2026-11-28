#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  printf 'Run this installer as root.\n' >&2
  exit 1
fi

package_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
service_user="${ASL_INFRA_USER:-asl-infra}"
service_group="${ASL_INFRA_GROUP:-asl-infra}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$script_dir/release-common.sh"
asl_load_paths
if [[ ! "$service_user" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] \
  || [[ ! "$service_group" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
  printf 'ASL_INFRA_USER and ASL_INFRA_GROUP must be portable system account names.\n' >&2
  exit 1
fi

for required in \
  asl-infra infra.example.toml asl-infra.service.in BUILD-INFO.json SHA256SUMS \
  upgrade.sh rollback.sh release-common.sh verify-release.sh \
  verify-offline-release.sh release_archive.py README.md LICENSE THIRD-PARTY.txt \
  sbom.cdx.json MPL-SOURCES.zip; do
  if [[ ! -f "$package_root/$required" ]]; then
    printf 'Package member is missing: %s\n' "$required" >&2
    exit 1
  fi
done
(
  cd "$package_root"
  sha256sum -c SHA256SUMS
)
asl_assert_release_root
if ! command -v systemctl >/dev/null 2>&1; then
  printf 'systemd is required to install the Linux infrastructure service.\n' >&2
  exit 1
fi
for occupied in \
  "$asl_bin_path" "$asl_release_root/current" "$asl_release_root/previous" \
  "$asl_unit_path" "$asl_tools_dir"; do
  if [[ -e "$occupied" || -L "$occupied" ]]; then
    printf 'Existing installation path found; refusing to overwrite: %s\n' "$occupied" >&2
    exit 1
  fi
done

binary_hash="$(sha256sum "$package_root/asl-infra" | awk '{print $1}')"
release_id="release-$binary_hash"
release_directory="$asl_release_root/$release_id"
if [[ -e "$release_directory" || -L "$release_directory" ]]; then
  printf 'Release directory already exists: %s\n' "$release_directory" >&2
  exit 1
fi

install_complete=0
release_created=0
current_created=0
launcher_created=0
tools_created=0
unit_created=0
temporary_unit=""
cleanup_install() {
  local status=$?
  trap - EXIT
  if (( ! install_complete )); then
    printf 'Installation did not complete; removing only newly created release tooling.\n' >&2
    [[ -n "$temporary_unit" ]] && rm -f -- "$temporary_unit"
    (( unit_created )) && rm -f -- "$asl_unit_path"
    (( launcher_created )) && rm -f -- "$asl_bin_path"
    (( current_created )) && asl_remove_pointer "$asl_release_root/current" || true
    if (( tools_created )) && [[ -d "$asl_tools_dir" && ! -L "$asl_tools_dir" ]]; then
      rm -rf -- "$asl_tools_dir"
    fi
    if (( release_created )) && [[ -d "$release_directory" && ! -L "$release_directory" ]]; then
      current_target="$(readlink -- "$asl_release_root/current" 2>/dev/null || true)"
      if [[ "$current_target" == "$release_id" ]]; then
        printf 'Retaining the new release because the current pointer still references it: %s\n' \
          "$release_directory" >&2
      else
        rm -rf -- "$release_directory"
      fi
    fi
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap cleanup_install EXIT

if ! getent group "$service_group" >/dev/null; then
  groupadd --system "$service_group"
fi
if ! id "$service_user" >/dev/null 2>&1; then
  useradd \
    --system \
    --gid "$service_group" \
    --home-dir "$asl_state_dir" \
    --shell /usr/sbin/nologin \
    "$service_user"
elif [[ "$(id -gn "$service_user")" != "$service_group" ]]; then
  printf 'Existing service user primary group does not match ASL_INFRA_GROUP.\n' >&2
  exit 1
fi

install -d -m 0755 "$asl_bin_dir"
asl_assert_root_controlled_chain "$asl_bin_dir" 'Release launcher'
install -d -m 0755 -o root -g root "$release_directory"
release_created=1
install -m 0755 -o root -g root "$package_root/asl-infra" "$release_directory/asl-infra"
install -m 0644 -o root -g root "$package_root/BUILD-INFO.json" "$release_directory/BUILD-INFO.json"
asl_set_pointer "$asl_release_root/current" "$release_id"
current_created=1
ln -s -- "$asl_release_root/current/asl-infra" "$asl_bin_path"
launcher_created=1
install -d -m 0755 -o root -g root "$asl_tools_dir"
tools_created=1
asl_assert_root_controlled_chain "$asl_tools_dir" 'Release tools'
for tool in upgrade.sh rollback.sh release-common.sh verify-release.sh \
  verify-offline-release.sh release_archive.py; do
  install -m 0755 -o root -g root "$package_root/$tool" "$asl_tools_dir/$tool"
done
asl_write_layout_file

install -d -m 0750 -o root -g "$service_group" "$asl_config_dir"
if [[ -L "$asl_config_path" || ( -e "$asl_config_path" && ! -f "$asl_config_path" ) ]]; then
  printf 'Configuration path must be a regular non-symlink file: %s\n' "$asl_config_path" >&2
  exit 1
elif [[ ! -e "$asl_config_path" ]]; then
  install -m 0640 -o root -g "$service_group" \
    "$package_root/infra.example.toml" "$asl_config_path"
  printf 'Created %s. Replace documentation-only external addresses before start.\n' \
    "$asl_config_path"
else
  printf 'Preserved existing %s.\n' "$asl_config_path"
fi

if [[ -L "$asl_state_dir" || ( -e "$asl_state_dir" && ! -d "$asl_state_dir" ) ]]; then
  printf 'State path must be a real directory: %s\n' "$asl_state_dir" >&2
  exit 1
fi
install -d -m 0750 -o "$service_user" -g "$service_group" "$asl_state_dir"
install -d -m 0755 "$asl_unit_dir"
asl_assert_root_controlled_chain "$asl_unit_dir" 'systemd unit'
temporary_unit="$(mktemp "$asl_unit_dir/.asl-infra.service.XXXXXX")"
sed \
  -e "s|@SERVICE_USER@|$service_user|g" \
  -e "s|@SERVICE_GROUP@|$service_group|g" \
  -e "s|@BIN_PATH@|$asl_bin_path|g" \
  -e "s|@CONFIG_PATH@|$asl_config_path|g" \
  -e "s|@STATE_PATH@|$asl_state_dir|g" \
  "$package_root/asl-infra.service.in" > "$temporary_unit"
install -m 0644 -o root -g root "$temporary_unit" "$asl_unit_path"
unit_created=1
rm -f "$temporary_unit"
temporary_unit=""

systemctl daemon-reload
install_complete=1

printf '\nInstalled ASL infrastructure.\n'
printf 'Review: %s\n' "$asl_config_path"
printf 'Start:  systemctl enable --now asl-infra\n'
printf 'Status: systemctl status asl-infra\n'
printf 'Logs:   journalctl -u asl-infra -f\n'
printf 'Upgrade: %s/upgrade.sh\n' "$asl_tools_dir"
printf 'Rollback: %s/rollback.sh\n' "$asl_tools_dir"
