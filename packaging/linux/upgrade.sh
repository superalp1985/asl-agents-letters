#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  printf 'Run the upgrade as root.\n' >&2
  exit 1
fi
if [[ $# -ne 5 ]]; then
  printf 'Usage: %s <artifact.tar.gz> <signature> <public-key.pem> <sha256-file> <trusted-key-sha256>\n' "$0" >&2
  exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$script_dir/release-common.sh"
asl_load_paths
asl_assert_release_root
asl_validate_installation

archive="$(realpath "$1")"
signature="$(realpath "$2")"
public_key="$(realpath "$3")"
hash_file="$(realpath "$4")"
trusted_key_hash="$5"
if [[ ! "$trusted_key_hash" =~ ^[[:xdigit:]]{64}$ ]]; then
  printf 'Trusted public-key SHA-256 must be 64 hexadecimal characters.\n' >&2
  exit 2
fi
for input in "$archive" "$signature" "$public_key" "$hash_file"; do
  if [[ ! -f "$input" ]]; then
    printf 'Release input is not a regular file: %s\n' "$input" >&2
    exit 1
  fi
done
archive_name="$(basename "$archive")"
if [[ ! "$archive_name" =~ ^[A-Za-z0-9._+-]+$ ]]; then
  printf 'Artifact filename contains unsupported characters.\n' >&2
  exit 1
fi
if [[ ! -x "$asl_tools_dir/verify-offline-release.sh" || ! -f "$asl_tools_dir/release_archive.py" ]]; then
  printf 'Installed offline release tools are missing; refusing to upgrade.\n' >&2
  exit 1
fi

old_id=""
old_previous=""
was_active=0
transaction_started=0
transaction_committed=0
new_directory_created=0
new_directory=""
new_id=""
stage="$(mktemp -d "$asl_release_root/.stage.XXXXXX")"
finish_upgrade() {
  local status=$?
  trap - EXIT
  if (( transaction_started && ! transaction_committed )); then
    printf 'Upgrade interrupted or failed; restoring previous release pointers.\n' >&2
    if [[ -n "$old_id" ]]; then
      asl_set_pointer "$asl_release_root/current" "$old_id" || true
    fi
    if [[ -n "$old_previous" ]]; then
      asl_set_pointer "$asl_release_root/previous" "$old_previous" || true
    else
      asl_remove_pointer "$asl_release_root/previous" || true
    fi
    systemctl daemon-reload || true
    if (( was_active )); then
      if ! systemctl restart asl-infra || ! asl_wait_active; then
        printf 'Previous binary pointer restored, but service did not recover; inspect systemd logs.\n' >&2
      fi
    fi
  fi
  if (( new_directory_created && ! transaction_committed )) \
    && [[ -n "$new_directory" && -d "$new_directory" && ! -L "$new_directory" ]]; then
    current_target="$(readlink -- "$asl_release_root/current" 2>/dev/null || true)"
    previous_target="$(readlink -- "$asl_release_root/previous" 2>/dev/null || true)"
    if [[ "$current_target" != "$new_id" && "$previous_target" != "$new_id" ]]; then
      rm -rf -- "$new_directory"
    else
      printf 'Retaining the failed release because a release pointer still references it: %s\n' \
        "$new_directory" >&2
    fi
  fi
  case "$stage" in
    "$asl_release_root"/.stage.*)
      if [[ -d "$stage" && ! -L "$stage" ]]; then
        rm -rf -- "$stage"
      fi
      ;;
    *)
      printf 'Refusing to remove unexpected staging path: %s\n' "$stage" >&2
      ;;
  esac
  exit "$status"
}
trap finish_upgrade EXIT

staged_archive="$stage/$archive_name"
staged_signature="$stage/$(basename "$signature")"
staged_public_key="$stage/$(basename "$public_key")"
staged_hash_file="$stage/$(basename "$hash_file")"
declare -A staged_names=()
for input_name in "$archive_name" "$(basename "$signature")" \
  "$(basename "$public_key")" "$(basename "$hash_file")"; do
  if [[ -n "${staged_names[$input_name]+present}" ]]; then
    printf 'Release inputs have conflicting filenames.\n' >&2
    exit 1
  fi
  staged_names["$input_name"]=1
done
install -m 0644 -- "$archive" "$staged_archive"
install -m 0644 -- "$signature" "$staged_signature"
install -m 0644 -- "$public_key" "$staged_public_key"
install -m 0644 -- "$hash_file" "$staged_hash_file"
bash "$asl_tools_dir/verify-offline-release.sh" \
  "$staged_archive" "$staged_signature" "$staged_public_key" "$staged_hash_file" "$trusted_key_hash"

package_root="$(python3 "$asl_tools_dir/release_archive.py" extract "$staged_archive" "$stage")"

binary_hash="$(sha256sum "$package_root/asl-infra" | awk '{print $1}')"
new_id="release-$binary_hash"
new_directory="$asl_release_root/$new_id"
if [[ -e "$new_directory" || -L "$new_directory" ]]; then
  if [[ ! -f "$new_directory/asl-infra" ]] \
    || [[ "$(sha256sum "$new_directory/asl-infra" | awk '{print $1}')" != "$binary_hash" ]]; then
    printf 'Release ID already exists with unexpected contents: %s\n' "$new_directory" >&2
    exit 1
  fi
  if [[ -e "$new_directory/BUILD-INFO.json" || -L "$new_directory/BUILD-INFO.json" ]]; then
    if [[ ! -f "$new_directory/BUILD-INFO.json" || -L "$new_directory/BUILD-INFO.json" ]] \
      || ! cmp -s -- "$package_root/BUILD-INFO.json" "$new_directory/BUILD-INFO.json"; then
      printf 'Release metadata conflicts with the authenticated package: %s\n' "$new_directory" >&2
      exit 1
    fi
  else
    install -m 0644 -o root -g root "$package_root/BUILD-INFO.json" "$new_directory/BUILD-INFO.json"
  fi
else
  install -d -m 0755 -o root -g root "$new_directory"
  new_directory_created=1
  install -m 0755 -o root -g root "$package_root/asl-infra" "$new_directory/asl-infra"
  install -m 0644 -o root -g root "$package_root/BUILD-INFO.json" "$new_directory/BUILD-INFO.json"
fi

old_id="$(asl_read_pointer "$asl_release_root/current")"
old_previous="$(asl_read_pointer "$asl_release_root/previous")"
launcher_needs_migration=0
if [[ -z "$old_id" ]]; then
  if [[ -f "$asl_bin_path" && ! -L "$asl_bin_path" ]]; then
    legacy_hash="$(sha256sum "$asl_bin_path" | awk '{print $1}')"
    old_id="release-$legacy_hash"
    legacy_directory="$asl_release_root/$old_id"
    if [[ ! -e "$legacy_directory" ]]; then
      install -d -m 0755 -o root -g root "$legacy_directory"
      install -m 0755 -o root -g root "$asl_bin_path" "$legacy_directory/asl-infra"
    elif [[ ! -f "$legacy_directory/asl-infra" ]] \
      || [[ "$(sha256sum "$legacy_directory/asl-infra" | awk '{print $1}')" != "$legacy_hash" ]]; then
      printf 'Legacy release path conflicts with existing data.\n' >&2
      exit 1
    fi
    launcher_needs_migration=1
  else
    printf 'No current managed release or legacy binary was found.\n' >&2
    exit 1
  fi
elif [[ ! -L "$asl_bin_path" ]]; then
  printf 'Managed release pointer exists but launcher is not the managed symlink.\n' >&2
  exit 1
fi

if [[ "$new_id" == "$old_id" ]]; then
  printf 'The requested release is already active.\n'
  exit 0
fi

new_version="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["version"])' "$package_root/BUILD-INFO.json")"
old_build_info="$asl_release_root/$old_id/BUILD-INFO.json"
if [[ -f "$old_build_info" && ! -L "$old_build_info" ]]; then
  old_version="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["version"])' "$old_build_info")"
  python3 "$asl_tools_dir/release_archive.py" require-upgrade "$new_version" "$old_version"
elif [[ "${ASL_INFRA_ALLOW_UNKNOWN_CURRENT_VERSION:-0}" != "1" ]]; then
  printf 'Current legacy release has no authenticated version metadata. Review its provenance, then set ASL_INFRA_ALLOW_UNKNOWN_CURRENT_VERSION=1 for this migration only.\n' >&2
  exit 1
else
  printf 'Warning: current release version is unknown; operator explicitly allowed one-time migration.\n' >&2
fi

was_active=0
service_state="$(asl_service_state)"
if [[ "$service_state" == "active" ]]; then
  was_active=1
fi

transaction_started=1
if (( launcher_needs_migration )); then
  asl_set_pointer "$asl_release_root/current" "$old_id"
  launcher_tmp="$asl_bin_dir/.asl-infra-link.$$"
  if [[ -e "$launcher_tmp" || -L "$launcher_tmp" ]]; then
    printf 'Temporary launcher path already exists: %s\n' "$launcher_tmp" >&2
    exit 1
  fi
  ln -s -- "$asl_release_root/current/asl-infra" "$launcher_tmp"
  if ! mv -Tf -- "$launcher_tmp" "$asl_bin_path"; then
    rm -f -- "$launcher_tmp"
    exit 1
  fi
fi

asl_set_pointer "$asl_release_root/previous" "$old_id"
asl_set_pointer "$asl_release_root/current" "$new_id"
systemctl daemon-reload
if (( was_active )); then
  systemctl restart asl-infra
  if ! asl_wait_active; then
    printf 'New release did not remain active.\n' >&2
    exit 1
  fi
fi
transaction_committed=1

if (( was_active )); then
  printf 'Upgrade active: %s\n' "$new_id"
else
  printf 'Upgrade installed but service was not active and was not started: %s\n' "$new_id"
fi
printf 'Previous release retained: %s\n' "$old_id"
