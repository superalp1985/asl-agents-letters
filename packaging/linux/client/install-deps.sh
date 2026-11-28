#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

package_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
packages_file="$package_root/APT-PACKAGES.txt"
deps_dir="$package_root/payload/apt-deps"
target_file="$deps_dir/TARGET-UBUNTU.txt"

die() {
  printf '%s\n' "$*" >&2
  exit 1
}

read_packages() {
  [[ -f "$packages_file" && ! -L "$packages_file" ]] \
    || die "Missing package list: $packages_file"
  mapfile -t packages < <(
    awk 'NF && $1 !~ /^#/ { print $1 }' "$packages_file"
  )
  [[ "${#packages[@]}" -gt 0 ]] || die 'The APT package list is empty.'
}

verify_target() {
  [[ -f /etc/os-release ]] || die '/etc/os-release is missing.'
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == "ubuntu" ]] || die "This dependency bundle is for Ubuntu, not ${ID:-unknown}."
  [[ "$(dpkg --print-architecture)" == "$expected_arch" ]] \
    || die "Dependency architecture mismatch: expected $expected_arch, found $(dpkg --print-architecture)."
  [[ "${VERSION_ID:-}" == "$expected_version" ]] \
    || die "Dependency bundle targets Ubuntu $expected_version, not ${VERSION_ID:-unknown}."
}

read_packages

if compgen -G "$deps_dir/*.deb" >/dev/null; then
  [[ -f "$target_file" && ! -L "$target_file" ]] \
    || die 'Bundled dependencies are missing TARGET-UBUNTU.txt.'
  [[ -f "$deps_dir/DEB-SHA256SUMS" && ! -L "$deps_dir/DEB-SHA256SUMS" ]] \
    || die 'Bundled dependencies are missing DEB-SHA256SUMS.'
  expected_version="$(
    sed -n 's/^VERSION_ID=//p' "$target_file" | head -n 1
  )"
  expected_arch="$(
    sed -n 's/^ARCH=//p' "$target_file" | head -n 1
  )"
  [[ -n "$expected_version" && -n "$expected_arch" ]] \
    || die 'TARGET-UBUNTU.txt is incomplete.'
  verify_target
  (
    cd "$deps_dir"
    sha256sum -c DEB-SHA256SUMS >/dev/null
  )

  command -v dpkg >/dev/null 2>&1 || die 'dpkg is required.'
  command -v dpkg-query >/dev/null 2>&1 || die 'dpkg-query is required.'
  selected=()
  for deb in "$deps_dir"/*.deb; do
    package="$(dpkg-deb -f "$deb" Package)"
    bundled_version="$(dpkg-deb -f "$deb" Version)"
    status="$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true)"
    installed_version="$(dpkg-query -W -f='${Version}' "$package" 2>/dev/null || true)"
    if [[ "$status" == "install ok installed" \
      && -n "$installed_version" \
      && "$(dpkg --compare-versions "$installed_version" ge "$bundled_version" \
        && printf yes || printf no)" == "yes" ]]; then
      continue
    fi
    selected+=("$deb")
  done
  if [[ "${#selected[@]}" -gt 0 ]]; then
    if [[ "$(id -u)" -eq 0 ]]; then
      dpkg -i "${selected[@]}"
      dpkg --configure -a
    else
      command -v sudo >/dev/null 2>&1 || die 'sudo is required to install system dependencies.'
      sudo dpkg -i "${selected[@]}"
      sudo dpkg --configure -a
    fi
  fi
  exit 0
fi

command -v apt-get >/dev/null 2>&1 || die 'apt-get is required.'
if [[ "$(id -u)" -eq 0 ]]; then
  apt-get update
  apt-get install --no-install-recommends -y "${packages[@]}"
else
  command -v sudo >/dev/null 2>&1 || die 'sudo is required to install system dependencies.'
  sudo apt-get update
  sudo apt-get install --no-install-recommends -y "${packages[@]}"
fi
