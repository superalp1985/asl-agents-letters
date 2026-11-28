#!/usr/bin/env bash

asl_client_die() {
  printf '%s\n' "$*" >&2
  exit 1
}

asl_client_validate_path() {
  local path="$1"
  local label="$2"
  if [[ -z "$path" || "$path" == *$'\n'* || "$path" == *$'\r'* || "$path" != /* ]]; then
    asl_client_die "$label must be a non-empty absolute path without control characters: $path"
  fi
  if [[ "$path" == *"'"* ]]; then
    asl_client_die "$label must not contain a single quote: $path"
  fi
  if [[ "$(realpath -m -- "$path")" != "$path" ]]; then
    asl_client_die "$label must be normalized and must not contain dot segments: $path"
  fi
}

asl_client_sed_escape() {
  printf '%s' "$1" | sed 's/[\\&|]/\\&/g'
}

asl_client_desktop_quote() {
  printf '%s' "$1" | sed \
    -e 's/\\/\\\\/g' \
    -e 's/"/\\"/g' \
    -e 's/%/%%/g' \
    -e 's/`/\\`/g' \
    -e 's/\$/\\$/g'
}

asl_client_write_layout() {
  local destination="$1"
  local directory
  directory="$(dirname "$destination")"
  install -d -m 0755 "$directory"
  local temporary="$destination.tmp.$$"
  [[ ! -e "$temporary" && ! -L "$temporary" ]] \
    || asl_client_die "Temporary layout already exists: $temporary"
  (
    umask 022
    printf 'ASL_CLIENT_PREFIX=%s\n' "$asl_client_prefix"
    printf 'ASL_HOME=%s\n' "$asl_home"
    printf 'ASL_RELEASE_ROOT=%s\n' "$asl_release_root"
    printf 'ASL_TOOLS_DIR=%s\n' "$asl_tools_dir"
    printf 'ASL_DESKTOP_DIR=%s\n' "$asl_desktop_dir"
    printf 'ASL_ICON_ROOT=%s\n' "$asl_icon_root"
    printf 'ASL_SERVICE_DIR=%s\n' "$asl_service_dir"
  ) > "$temporary"
  mv -T -- "$temporary" "$destination"
}

asl_client_load_layout() {
  local layout_file="$1"
  [[ -f "$layout_file" && ! -L "$layout_file" ]] \
    || asl_client_die "Installed client layout is missing or unsafe: $layout_file"
  local line key value
  local -A values=()
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" == *=* ]] || asl_client_die "Invalid installed layout line."
    key="${line%%=*}"
    value="${line#*=}"
    case "$key" in
      ASL_CLIENT_PREFIX|ASL_HOME|ASL_RELEASE_ROOT|ASL_TOOLS_DIR|ASL_DESKTOP_DIR|ASL_ICON_ROOT|ASL_SERVICE_DIR)
        ;;
      *)
        asl_client_die "Unknown installed layout key: $key"
        ;;
    esac
    [[ -z "${values[$key]+present}" ]] \
      || asl_client_die "Installed layout repeats key: $key"
    asl_client_validate_path "$value" "$key"
    values["$key"]="$value"
  done < "$layout_file"
  [[ "${#values[@]}" -eq 7 ]] \
    || asl_client_die "Installed client layout is incomplete: $layout_file"

  asl_client_prefix="${values[ASL_CLIENT_PREFIX]}"
  asl_client_home="${values[ASL_HOME]}"
  asl_release_root="${values[ASL_RELEASE_ROOT]}"
  asl_tools_dir="${values[ASL_TOOLS_DIR]}"
  asl_desktop_dir="${values[ASL_DESKTOP_DIR]}"
  asl_icon_root="${values[ASL_ICON_ROOT]}"
  asl_service_dir="${values[ASL_SERVICE_DIR]}"
}

asl_client_user_unit_dir() {
  printf '%s\n' "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
}

asl_client_check_binary_dependencies() {
  local payload_bin="$1"
  local executable missing
  for executable in asl asl-core asl-net asl-worker asl-extractor asl-ui; do
    missing="$(
      ldd "$payload_bin/$executable" 2>/dev/null \
        | awk '/not found/ {print $1}' \
        | sort -u \
        | paste -sd, - || true
    )"
    if [[ -n "$missing" ]]; then
      printf 'Executable %s has unresolved shared libraries: %s\n' "$executable" "$missing" >&2
      printf 'Install the APT dependencies listed in APT-DEPENDENCIES.txt, then retry.\n' >&2
      return 1
    fi
  done
}

asl_client_managed_symlink() {
  local path="$1"
  local expected="$2"
  [[ -L "$path" && "$(readlink -- "$path")" == "$expected" ]]
}
