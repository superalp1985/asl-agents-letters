#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  printf 'Run rollback as root.\n' >&2
  exit 1
fi
if [[ $# -ne 0 ]]; then
  printf 'Usage: %s\n' "$0" >&2
  exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$script_dir/release-common.sh"
asl_load_paths
asl_assert_release_root
asl_validate_installation

current_id="$(asl_read_pointer "$asl_release_root/current")"
previous_id="$(asl_read_pointer "$asl_release_root/previous")"
if [[ -z "$current_id" || -z "$previous_id" ]]; then
  printf 'Both current and previous releases are required for rollback.\n' >&2
  exit 1
fi
if [[ "$current_id" == "$previous_id" ]]; then
  printf 'Current and previous release pointers are identical.\n' >&2
  exit 1
fi

was_active=0
service_state="$(asl_service_state)"
if [[ "$service_state" == "active" ]]; then
  was_active=1
fi

transaction_started=1
transaction_committed=0
restore_rollback() {
  local status=$?
  trap - EXIT
  if (( transaction_started && ! transaction_committed )); then
    printf 'Rollback failed; restoring the original release pointers.\n' >&2
    asl_set_pointer "$asl_release_root/current" "$current_id" || true
    asl_set_pointer "$asl_release_root/previous" "$previous_id" || true
    systemctl daemon-reload || true
    if (( was_active )); then
      if ! systemctl restart asl-infra || ! asl_wait_active; then
        printf 'Original release pointer restored, but service did not recover; inspect systemd logs.\n' >&2
      fi
    fi
  fi
  exit "$status"
}
trap restore_rollback EXIT

asl_set_pointer "$asl_release_root/current" "$previous_id"
asl_set_pointer "$asl_release_root/previous" "$current_id"
systemctl daemon-reload
if (( was_active )); then
  systemctl restart asl-infra
  if ! asl_wait_active; then
    printf 'Rollback target did not remain active.\n' >&2
    exit 1
  fi
fi
transaction_committed=1

if (( was_active )); then
  printf 'Rolled back and restarted service: %s\n' "$previous_id"
else
  printf 'Rolled back binary pointer; service was not active and was not started: %s\n' "$previous_id"
fi
