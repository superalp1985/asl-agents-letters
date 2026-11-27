#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  printf 'Run this installer as root.\n' >&2
  exit 1
fi

package_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
service_user="${ASL_INFRA_USER:-asl-infra}"
service_group="${ASL_INFRA_GROUP:-asl-infra}"
prefix="${ASL_INFRA_PREFIX:-/usr/local}"
bin_dir="${ASL_INFRA_BIN_DIR:-$prefix/bin}"
config_dir="${ASL_INFRA_CONFIG_DIR:-/etc/asl-infra}"
state_dir="${ASL_INFRA_STATE_DIR:-/var/lib/asl-infra}"
unit_dir="${ASL_INFRA_SYSTEMD_DIR:-/etc/systemd/system}"
config_path="$config_dir/infra.toml"
bin_path="$bin_dir/asl-infra"

for required in asl-infra infra.example.toml asl-infra.service.in; do
  if [[ ! -f "$package_root/$required" ]]; then
    printf 'Package member is missing: %s\n' "$required" >&2
    exit 1
  fi
done

if ! getent group "$service_group" >/dev/null; then
  groupadd --system "$service_group"
fi
if ! id "$service_user" >/dev/null 2>&1; then
  useradd \
    --system \
    --gid "$service_group" \
    --home-dir "$state_dir" \
    --shell /usr/sbin/nologin \
    "$service_user"
fi

install -d -m 0755 "$bin_dir"
install -m 0755 "$package_root/asl-infra" "$bin_path"

install -d -m 0750 -o root -g "$service_group" "$config_dir"
if [[ ! -e "$config_path" ]]; then
  install -m 0640 -o root -g "$service_group" \
    "$package_root/infra.example.toml" "$config_path"
  printf 'Created %s. Replace documentation-only external addresses before start.\n' \
    "$config_path"
else
  printf 'Preserved existing %s.\n' "$config_path"
fi

install -d -m 0750 -o "$service_user" -g "$service_group" "$state_dir"
install -d -m 0755 "$unit_dir"
temporary_unit="$(mktemp)"
trap 'rm -f "$temporary_unit"' EXIT
sed \
  -e "s|@SERVICE_USER@|$service_user|g" \
  -e "s|@SERVICE_GROUP@|$service_group|g" \
  -e "s|@BIN_PATH@|$bin_path|g" \
  -e "s|@CONFIG_PATH@|$config_path|g" \
  -e "s|@STATE_PATH@|$state_dir|g" \
  "$package_root/asl-infra.service.in" > "$temporary_unit"
install -m 0644 "$temporary_unit" "$unit_dir/asl-infra.service"

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
fi

printf '\nInstalled ASL infrastructure.\n'
printf 'Review: %s\n' "$config_path"
printf 'Start:  systemctl enable --now asl-infra\n'
printf 'Status: systemctl status asl-infra\n'
printf 'Logs:   journalctl -u asl-infra -f\n'
