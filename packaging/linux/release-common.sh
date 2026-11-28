#!/usr/bin/env bash

asl_release_common_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

asl_validate_path_value() {
  local path="$1"
  local label="$2"
  if [[ ! "$path" =~ ^/[A-Za-z0-9._+:/-]+$ ]] \
    || [[ "$(realpath -m -- "$path")" != "$path" ]]; then
    printf '%s must be a normalized absolute path using portable path characters: %s\n' \
      "$label" "$path" >&2
    return 1
  fi
}

asl_assert_root_controlled_chain() {
  local cursor="$1"
  local label="$2"
  if [[ ! -d "$cursor" ]]; then
    cursor="$(dirname "$cursor")"
  fi
  local owner mode
  while :; do
    if [[ ! -d "$cursor" || -L "$cursor" ]]; then
      printf '%s path must use real directories: %s\n' "$label" "$cursor" >&2
      return 1
    fi
    owner="$(stat -c '%u' "$cursor")"
    mode="$(stat -c '%a' "$cursor")"
    if [[ "$owner" != 0 ]] || (( (8#$mode & 022) != 0 )); then
      printf '%s path must be root-owned and not group/world writable: %s\n' \
        "$label" "$cursor" >&2
      return 1
    fi
    [[ "$cursor" == "/" ]] && break
    cursor="$(dirname "$cursor")"
  done
}

asl_load_layout_file() {
  local layout_file="$1"
  asl_validate_path_value "$layout_file" 'ASL infrastructure layout file'
  if [[ ! -f "$layout_file" || -L "$layout_file" ]]; then
    printf 'Installed layout must be a regular non-symlink file: %s\n' "$layout_file" >&2
    return 1
  fi
  local owner mode
  owner="$(stat -c '%u' "$layout_file")"
  mode="$(stat -c '%a' "$layout_file")"
  if [[ "$owner" != 0 ]] || (( (8#$mode & 022) != 0 )); then
    printf 'Installed layout must be root-owned and not group/world writable: %s\n' \
      "$layout_file" >&2
    return 1
  fi
  asl_assert_root_controlled_chain "$(dirname "$layout_file")" 'Installed layout'

  local line key value
  declare -A layout=()
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ ! "$line" =~ ^([A-Z_]+)=(/.+)$ ]]; then
      printf 'Installed layout contains an invalid line.\n' >&2
      return 1
    fi
    key="${BASH_REMATCH[1]}"
    value="${BASH_REMATCH[2]}"
    case "$key" in
      ASL_BIN_DIR|ASL_CONFIG_DIR|ASL_STATE_DIR|ASL_UNIT_DIR|ASL_RELEASE_DIR|ASL_TOOLS_DIR)
        ;;
      *)
        printf 'Installed layout contains an unknown key: %s\n' "$key" >&2
        return 1
        ;;
    esac
    if [[ -n "${layout[$key]+present}" ]]; then
      printf 'Installed layout repeats a key: %s\n' "$key" >&2
      return 1
    fi
    asl_validate_path_value "$value" "$key"
    layout["$key"]="$value"
  done < "$layout_file"
  if [[ "${#layout[@]}" -ne 6 ]]; then
    printf 'Installed layout is incomplete: %s\n' "$layout_file" >&2
    return 1
  fi

  asl_bin_dir="${layout[ASL_BIN_DIR]}"
  asl_config_dir="${layout[ASL_CONFIG_DIR]}"
  asl_state_dir="${layout[ASL_STATE_DIR]}"
  asl_unit_dir="${layout[ASL_UNIT_DIR]}"
  asl_release_root="${layout[ASL_RELEASE_DIR]}"
  asl_tools_dir="${layout[ASL_TOOLS_DIR]}"

  local variable expected
  for variable in ASL_INFRA_BIN_DIR ASL_INFRA_CONFIG_DIR ASL_INFRA_STATE_DIR \
    ASL_INFRA_SYSTEMD_DIR ASL_INFRA_RELEASE_DIR ASL_INFRA_TOOLS_DIR; do
    case "$variable" in
      ASL_INFRA_BIN_DIR) expected="$asl_bin_dir" ;;
      ASL_INFRA_CONFIG_DIR) expected="$asl_config_dir" ;;
      ASL_INFRA_STATE_DIR) expected="$asl_state_dir" ;;
      ASL_INFRA_SYSTEMD_DIR) expected="$asl_unit_dir" ;;
      ASL_INFRA_RELEASE_DIR) expected="$asl_release_root" ;;
      ASL_INFRA_TOOLS_DIR) expected="$asl_tools_dir" ;;
    esac
    if [[ -v "$variable" && "${!variable}" != "$expected" ]]; then
      printf '%s conflicts with the installed layout.\n' "$variable" >&2
      return 1
    fi
  done
}

asl_write_layout_file() {
  local layout_file="$asl_tools_dir/install-layout.conf"
  if [[ -e "$layout_file" || -L "$layout_file" ]]; then
    printf 'Installed layout already exists: %s\n' "$layout_file" >&2
    return 1
  fi
  local temporary="$asl_tools_dir/.install-layout.conf.$$"
  if [[ -e "$temporary" || -L "$temporary" ]]; then
    printf 'Temporary installed layout already exists: %s\n' "$temporary" >&2
    return 1
  fi
  (
    umask 022
    printf 'ASL_BIN_DIR=%s\n' "$asl_bin_dir"
    printf 'ASL_CONFIG_DIR=%s\n' "$asl_config_dir"
    printf 'ASL_STATE_DIR=%s\n' "$asl_state_dir"
    printf 'ASL_UNIT_DIR=%s\n' "$asl_unit_dir"
    printf 'ASL_RELEASE_DIR=%s\n' "$asl_release_root"
    printf 'ASL_TOOLS_DIR=%s\n' "$asl_tools_dir"
  ) > "$temporary"
  chown root:root "$temporary"
  chmod 0644 "$temporary"
  mv -T -- "$temporary" "$layout_file"
}

asl_load_paths() {
  local layout_file="${ASL_INFRA_LAYOUT_FILE:-$asl_release_common_dir/install-layout.conf}"
  if [[ -v ASL_INFRA_LAYOUT_FILE && ! -e "$layout_file" && ! -L "$layout_file" ]]; then
    printf 'Explicit ASL_INFRA_LAYOUT_FILE does not exist: %s\n' "$layout_file" >&2
    return 1
  fi
  if [[ -e "$layout_file" || -L "$layout_file" ]]; then
    asl_load_layout_file "$layout_file"
    if [[ -v ASL_INFRA_PREFIX ]]; then
      printf 'ASL_INFRA_PREFIX cannot override a persisted installed layout.\n' >&2
      return 1
    fi
  else
    local prefix="${ASL_INFRA_PREFIX:-/usr/local}"
    asl_bin_dir="${ASL_INFRA_BIN_DIR:-$prefix/bin}"
    asl_config_dir="${ASL_INFRA_CONFIG_DIR:-/etc/asl-infra}"
    asl_state_dir="${ASL_INFRA_STATE_DIR:-/var/lib/asl-infra}"
    asl_unit_dir="${ASL_INFRA_SYSTEMD_DIR:-/etc/systemd/system}"
    asl_release_root="${ASL_INFRA_RELEASE_DIR:-$prefix/lib/asl-infra/releases}"
    asl_tools_dir="${ASL_INFRA_TOOLS_DIR:-$prefix/libexec/asl-infra}"
  fi
  asl_bin_path="$asl_bin_dir/asl-infra"
  asl_config_path="$asl_config_dir/infra.toml"
  asl_unit_path="$asl_unit_dir/asl-infra.service"

  local path label
  for label in BIN_DIR CONFIG_DIR STATE_DIR UNIT_DIR RELEASE_DIR TOOLS_DIR; do
    case "$label" in
      BIN_DIR) path="$asl_bin_dir" ;;
      CONFIG_DIR) path="$asl_config_dir" ;;
      STATE_DIR) path="$asl_state_dir" ;;
      UNIT_DIR) path="$asl_unit_dir" ;;
      RELEASE_DIR) path="$asl_release_root" ;;
      TOOLS_DIR) path="$asl_tools_dir" ;;
    esac
    asl_validate_path_value "$path" "ASL $label"
  done
}

asl_assert_release_root() {
  local canonical
  canonical="$(realpath -m "$asl_release_root")"
  if [[ "$canonical" != "$asl_release_root" ]]; then
    printf 'Release directory must not traverse a symlink: %s\n' "$asl_release_root" >&2
    return 1
  fi
  install -d -m 0755 -o root -g root "$asl_release_root"
  if [[ -L "$asl_release_root" ]]; then
    printf 'Release directory must not traverse a symlink: %s\n' "$asl_release_root" >&2
    return 1
  fi
  local cursor="$asl_release_root" owner mode
  while :; do
    owner="$(stat -c '%u' "$cursor")"
    mode="$(stat -c '%a' "$cursor")"
    if [[ "$owner" != 0 ]] || (( (8#$mode & 022) != 0 )); then
      printf 'Release path must be root-owned and not group/world writable: %s\n' "$cursor" >&2
      return 1
    fi
    [[ "$cursor" == "/" ]] && break
    cursor="$(dirname "$cursor")"
  done
}

asl_read_pointer() {
  local path="$1"
  if [[ ! -e "$path" && ! -L "$path" ]]; then
    printf ''
    return 0
  fi
  if [[ ! -L "$path" ]]; then
    printf 'Release pointer is not a symlink: %s\n' "$path" >&2
    return 1
  fi
  local target
  target="$(readlink -- "$path")"
  if [[ ! "$target" =~ ^release-[0-9a-f]{64}$ ]] \
    || [[ ! -d "$asl_release_root/$target" || -L "$asl_release_root/$target" ]] \
    || [[ ! -f "$asl_release_root/$target/asl-infra" || -L "$asl_release_root/$target/asl-infra" ]] \
    || [[ ! -x "$asl_release_root/$target/asl-infra" ]] \
  then
    printf 'Release pointer has an invalid target: %s\n' "$path" >&2
    return 1
  fi
  printf '%s' "$target"
}

asl_set_pointer() {
  local path="$1"
  local target="$2"
  if [[ ! "$target" =~ ^release-[0-9a-f]{64}$ ]] \
    || [[ ! -d "$asl_release_root/$target" || -L "$asl_release_root/$target" ]] \
    || [[ ! -f "$asl_release_root/$target/asl-infra" || -L "$asl_release_root/$target/asl-infra" ]] \
    || [[ ! -x "$asl_release_root/$target/asl-infra" ]]; then
    printf 'Refusing invalid release pointer target: %s\n' "$target" >&2
    return 1
  fi
  local temporary="$path.tmp.$$"
  if [[ -e "$temporary" || -L "$temporary" ]]; then
    printf 'Temporary release pointer already exists: %s\n' "$temporary" >&2
    return 1
  fi
  ln -s -- "$target" "$temporary"
  if ! mv -Tf -- "$temporary" "$path"; then
    rm -f -- "$temporary"
    return 1
  fi
}

asl_remove_pointer() {
  local path="$1"
  if [[ -L "$path" ]]; then
    asl_read_pointer "$path" >/dev/null
    rm -- "$path"
  elif [[ -e "$path" ]]; then
    printf 'Refusing to remove a non-symlink release pointer: %s\n' "$path" >&2
    return 1
  fi
}

asl_validate_installation() {
  if [[ "$(realpath -m -- "$asl_release_common_dir")" != "$asl_tools_dir" ]]; then
    printf 'Release tooling is not running from the configured tools directory.\n' >&2
    return 1
  fi
  local layout_file="$asl_tools_dir/install-layout.conf"
  if [[ ! -f "$layout_file" || -L "$layout_file" ]]; then
    printf 'Installed layout metadata is missing: %s\n' "$layout_file" >&2
    return 1
  fi
  asl_assert_root_controlled_chain "$asl_tools_dir" 'Release tools'
  asl_assert_root_controlled_chain "$asl_bin_dir" 'Release launcher'
  asl_assert_root_controlled_chain "$asl_unit_dir" 'systemd unit'
  if [[ ! -f "$asl_unit_path" ]]; then
    printf 'systemd unit is missing: %s\n' "$asl_unit_path" >&2
    return 1
  fi
  if ! grep -Fqx "ExecStart=$asl_bin_path $asl_config_path" "$asl_unit_path"; then
    printf 'The installed unit does not use the managed binary/config paths; refusing automatic update.\n' >&2
    return 1
  fi
  if [[ -L "$asl_bin_path" ]]; then
    if [[ "$(readlink -- "$asl_bin_path")" != "$asl_release_root/current/asl-infra" ]]; then
      printf 'The launcher symlink is not managed by the ASL release tooling.\n' >&2
      return 1
    fi
  elif [[ -e "$asl_bin_path" && ! -f "$asl_bin_path" ]]; then
    printf 'The launcher path is not a regular file: %s\n' "$asl_bin_path" >&2
    return 1
  fi
}

asl_wait_active() {
  local timeout="${ASL_INFRA_START_TIMEOUT:-30}"
  if [[ ! "$timeout" =~ ^[1-9][0-9]?$ ]] || (( timeout > 120 )); then
    printf 'ASL_INFRA_START_TIMEOUT must be between 1 and 120 seconds.\n' >&2
    return 1
  fi
  local elapsed=0 consecutive=0
  while (( elapsed < timeout )); do
    if systemctl is-active --quiet asl-infra; then
      consecutive=$((consecutive + 1))
      if (( consecutive >= 3 )); then
        return 0
      fi
    else
      consecutive=0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  return 1
}

asl_service_state() {
  local state
  state="$(systemctl show --property=ActiveState --value asl-infra)" || {
    printf 'Unable to read the systemd service state.\n' >&2
    return 1
  }
  case "$state" in
    active|inactive|failed)
      printf '%s' "$state"
      ;;
    *)
      printf 'Service is in a transitional or unknown state: %s\n' "$state" >&2
      return 1
      ;;
  esac
}
