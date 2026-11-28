#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 022

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="${ASL_CLIENT_OUTPUT_DIR:-$repo/target/release-packages}"
target="${ASL_CLIENT_TARGET:-}"
offline="${ASL_CARGO_OFFLINE:-0}"
allow_dirty=0
build_deb=1
keep_symbols="${ASL_CLIENT_KEEP_SYMBOLS:-0}"
apt_deps_dir="${ASL_CLIENT_APT_DEPS_DIR:-}"

usage() {
  cat <<'EOF'
Usage: package-linux-client.sh [options] [output-directory]

Build the complete Ubuntu 22.04+ ASL desktop client as deterministic tar.gz
and .deb release artifacts. The build requires Rust and dpkg-deb; installed
users do not require Rust.

Options:
  --output-dir DIR       Release output directory
  --target TRIPLE        Linux target (default: rustc host)
  --offline              Use the existing Cargo cache only
  --allow-dirty          Permit a non-release build from a dirty worktree
  --no-deb               Build only the tar.gz package
  --apt-deps-dir DIR     Bundle pre-downloaded Ubuntu .deb dependencies from DIR
  --keep-symbols         Do not run strip on copied executables
  -h, --help             Show this help

Environment:
  ASL_CLIENT_TARGET, ASL_CLIENT_OUTPUT_DIR, ASL_CLIENT_KEEP_SYMBOLS,
  ASL_CLIENT_APT_DEPS_DIR, ASL_CARGO_OFFLINE=1,
  ASL_RELEASE_ALLOW_DIRTY=1, SOURCE_DATE_EPOCH
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      output_dir="$2"
      shift 2
      ;;
    --target)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      target="$2"
      shift 2
      ;;
    --offline)
      offline=1
      shift
      ;;
    --allow-dirty)
      allow_dirty=1
      shift
      ;;
    --no-deb)
      build_deb=0
      shift
      ;;
    --apt-deps-dir)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      apt_deps_dir="$2"
      shift 2
      ;;
    --keep-symbols)
      keep_symbols=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      usage >&2
      exit 2
      ;;
    *)
      if [[ "$output_dir" != "$repo/target/release-packages" ]]; then
        printf 'Only one positional output directory is accepted.\n' >&2
        exit 2
      fi
      output_dir="$1"
      shift
      ;;
  esac
done
if [[ $# -ne 0 ]]; then
  usage >&2
  exit 2
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  printf 'Build the Linux client on Linux. Cross-packaging from Windows is not supported.\n' >&2
  exit 1
fi
apt_packages_file="$repo/packaging/linux/client/apt-packages.txt"
[[ -f "$apt_packages_file" && ! -L "$apt_packages_file" ]] \
  || { printf 'Missing APT package list: %s\n' "$apt_packages_file" >&2; exit 1; }
mapfile -t apt_packages < <(awk 'NF && $1 !~ /^#/ { print $1 }' "$apt_packages_file")
[[ "${#apt_packages[@]}" -gt 0 ]] \
  || { printf 'The APT package list is empty.\n' >&2; exit 1; }
if [[ -n "$apt_deps_dir" ]]; then
  [[ -d "$apt_deps_dir" && ! -L "$apt_deps_dir" ]] \
    || { printf 'APT dependency bundle is not a real directory: %s\n' "$apt_deps_dir" >&2; exit 1; }
  for required_dep_file in TARGET-UBUNTU.txt APT-PACKAGES.txt DEB-SHA256SUMS; do
    [[ -f "$apt_deps_dir/$required_dep_file" && ! -L "$apt_deps_dir/$required_dep_file" ]] \
      || { printf 'APT dependency bundle member is missing or unsafe: %s\n' "$required_dep_file" >&2; exit 1; }
  done
  if ! compgen -G "$apt_deps_dir/*.deb" >/dev/null; then
    printf 'APT dependency bundle contains no .deb files.\n' >&2
    exit 1
  fi
  mapfile -t bundled_apt_packages < <(
    awk 'NF && $1 !~ /^#/ { print $1 }' "$apt_deps_dir/APT-PACKAGES.txt"
  )
  if [[ "$(printf '%s\n' "${apt_packages[@]}")" != "$(printf '%s\n' "${bundled_apt_packages[@]}")" ]]; then
    printf 'APT dependency bundle package list does not match the client manifest.\n' >&2
    exit 1
  fi
  (
    cd "$apt_deps_dir"
    sha256sum -c DEB-SHA256SUMS >/dev/null
  )
fi
for command in cargo rustc python3 git tar gzip sha256sum install; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'Required build command is missing: %s\n' "$command" >&2
    exit 1
  }
done
if (( build_deb )) && ! command -v dpkg-deb >/dev/null 2>&1; then
  printf 'dpkg-deb is required for the .deb artifact; install dpkg-dev or pass --no-deb.\n' >&2
  exit 1
fi
if (( ! keep_symbols )); then
  command -v strip >/dev/null 2>&1 || {
    printf 'strip is required unless --keep-symbols is selected.\n' >&2
    exit 1
  }
fi

metadata_args=(metadata --manifest-path "$repo/Cargo.toml" --no-deps --format-version 1 --locked)
if [[ "${ASL_CARGO_OFFLINE:-0}" == "1" ]]; then
  metadata_args+=(--offline)
fi
metadata="$(cargo "${metadata_args[@]}")"
version="$(python3 -c 'import json,sys; data=json.load(sys.stdin); print(next(p["version"] for p in data["packages"] if p["name"]=="asl-app"))' <<<"$metadata")"
target_dir="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])' <<<"$metadata")"
host_target="$(rustc -vV | sed -n 's/^host: //p')"
target="${target:-$host_target}"
case "$target" in
  x86_64-*-linux-gnu) arch=x86_64; deb_arch=amd64 ;;
  aarch64-*-linux-gnu) arch=aarch64; deb_arch=arm64 ;;
  *)
    printf 'The Ubuntu client target must be x86_64 or aarch64 GNU/Linux: %s\n' "$target" >&2
    exit 1
    ;;
esac
if [[ -n "$apt_deps_dir" ]]; then
  bundled_arch="$(sed -n 's/^ARCH=//p' "$apt_deps_dir/TARGET-UBUNTU.txt" | head -n 1)"
  [[ "$bundled_arch" == "$deb_arch" ]] \
    || { printf 'APT dependency architecture %s does not match package architecture %s.\n' "$bundled_arch" "$deb_arch" >&2; exit 1; }
fi
if [[ ! "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  printf 'Linux client releases require a stable X.Y.Z version.\n' >&2
  exit 1
fi

if git -C "$repo" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  release_epoch="${SOURCE_DATE_EPOCH:-$(git -C "$repo" show -s --format=%ct HEAD)}"
  commit="$(git -C "$repo" rev-parse HEAD)"
  if [[ "${ASL_RELEASE_ALLOW_DIRTY:-0}" != "1" && "$allow_dirty" -ne 1 ]]; then
    if [[ -n "$(git -C "$repo" status --porcelain --untracked-files=normal)" ]]; then
      printf 'Release packages require a clean worktree. Use --allow-dirty only for local test packages.\n' >&2
      exit 1
    fi
  fi
else
  if [[ "${ASL_RELEASE_ALLOW_DIRTY:-0}" != "1" && "$allow_dirty" -ne 1 ]]; then
    printf 'A source archive build requires --allow-dirty and ASL_RELEASE_COMMIT.\n' >&2
    exit 1
  fi
  release_epoch="${SOURCE_DATE_EPOCH:-}"
  commit="${ASL_RELEASE_COMMIT:-}"
  if [[ -z "$release_epoch" || -z "$commit" ]]; then
    printf 'Source archive builds require SOURCE_DATE_EPOCH and ASL_RELEASE_COMMIT.\n' >&2
    exit 1
  fi
fi
if [[ ! "$release_epoch" =~ ^(0|[1-9][0-9]{0,11})$ ]] \
  || (( release_epoch < 315532800 || release_epoch > 4354819198 )); then
  printf 'SOURCE_DATE_EPOCH must fit the deterministic archive timestamp range.\n' >&2
  exit 1
fi
if [[ ! "$commit" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]]; then
  printf 'The release commit must be a full lowercase Git object ID.\n' >&2
  exit 1
fi
build_time="$(date -u -d "@$release_epoch" +%Y-%m-%dT%H:%M:%SZ)"
glibc_baseline="${ASL_DEB_LIBC6_MIN:-2.35}"
if [[ "$target" == "$host_target" ]] && command -v getconf >/dev/null 2>&1; then
  host_glibc="$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}' || true)"
  if [[ "$host_glibc" =~ ^[0-9]+\.[0-9]+$ ]] \
    && [[ "$(printf '%s\n%s\n' "$glibc_baseline" "$host_glibc" | sort -V | tail -n1)" == "$host_glibc" ]]; then
    glibc_baseline="$host_glibc"
  fi
fi
if [[ ! "$glibc_baseline" =~ ^[0-9]+\.[0-9]+$ ]]; then
  printf 'ASL_DEB_LIBC6_MIN must be a glibc version such as 2.35.\n' >&2
  exit 1
fi

stage="$(mktemp -d)"
temporary_paths=()
cleanup() {
  local status=$?
  trap - EXIT
  rm -rf -- "$stage"
  local path
  for path in "${temporary_paths[@]}"; do
    [[ -z "$path" ]] || rm -f -- "$path"
  done
  exit "$status"
}
trap cleanup EXIT

build_args=(
  build
  --manifest-path "$repo/Cargo.toml"
  -p asl-app
  --bins
  --features desktop-ui
  --release
  --locked
)
if [[ "$target" != "$host_target" ]]; then
  build_args+=(--target "$target")
fi
if (( offline )); then
  build_args+=(--offline)
fi
cargo "${build_args[@]}"

binary_dir="$target_dir/release"
if [[ "$target" != "$host_target" ]]; then
  binary_dir="$target_dir/$target/release"
fi
executables=(asl asl-core asl-net asl-worker asl-extractor asl-ui)
package_name="asl-client-linux-$arch-$version"
package_root="$stage/$package_name"
payload="$package_root/payload"
mkdir -p \
  "$payload/bin" \
  "$payload/share/applications" \
  "$payload/share/icons/hicolor/scalable/apps" \
  "$payload/share/icons/hicolor/256x256/apps" \
  "$payload/config" \
  "$payload/systemd" \
  "$payload/apt-deps"

for executable in "${executables[@]}"; do
  source="$binary_dir/$executable"
  if [[ ! -f "$source" || -L "$source" || ! -x "$source" ]]; then
    printf 'Expected release executable is missing or unsafe: %s\n' "$source" >&2
    exit 1
  fi
  install -m 0755 "$source" "$payload/bin/$executable"
  if (( ! keep_symbols )); then
    strip --strip-unneeded "$payload/bin/$executable"
  fi
done

install -m 0644 "$repo/packaging/linux/client/asl.desktop" "$payload/share/applications/asl.desktop"
install -m 0644 "$repo/docs/assets/asl-pixel-icon.svg" "$payload/share/icons/hicolor/scalable/apps/asl.svg"
install -m 0644 "$repo/docs/assets/asl-pixel-icon-256.png" "$payload/share/icons/hicolor/256x256/apps/asl.png"
install -m 0644 "$repo/packaging/linux/client/asl.env.example" "$payload/config/asl.env.example"
install -m 0644 "$repo/packaging/linux/client/asl-core.service.in" "$payload/systemd/asl-core.service.in"
install -m 0755 "$repo/packaging/linux/client/asl-launch.in" "$payload/bin/asl-launch.in"
install -m 0755 "$repo/packaging/linux/client/asl-core-service.in" "$payload/bin/asl-core-service.in"
install -m 0755 "$repo/packaging/linux/client/install-deps.sh" "$package_root/install-deps.sh"

for tool in install.sh uninstall.sh upgrade.sh verify.sh client-common.sh release_archive.py; do
  install -m 0755 "$repo/packaging/linux/client/$tool" "$package_root/$tool"
done
install -m 0644 "$repo/packaging/linux/client/README.md" "$package_root/README.md"
install -m 0644 "$repo/LICENSE" "$package_root/LICENSE"

if [[ -n "$apt_deps_dir" ]]; then
  for deb in "$apt_deps_dir"/*.deb; do
    install -m 0644 "$deb" "$payload/apt-deps/$(basename "$deb")"
  done
  install -m 0644 "$apt_deps_dir/TARGET-UBUNTU.txt" "$payload/apt-deps/TARGET-UBUNTU.txt"
  install -m 0644 "$apt_deps_dir/DEB-SHA256SUMS" "$payload/apt-deps/DEB-SHA256SUMS"
fi

notice_args=(
  "$repo/scripts/package-linux-notices.py"
  --repo "$repo"
  --output "$package_root"
  --target "$target"
  --version "$version"
  --source-date-epoch "$release_epoch"
  --component-name asl-client
  --runtime-label "desktop client"
)
if (( offline )); then
  notice_args+=(--offline)
fi
python3 "${notice_args[@]}"

python3 - "$package_root/BUILD-INFO.json" "$version" "$commit" "$target" "$arch" \
  "$release_epoch" "$build_time" "$glibc_baseline" <<'PY'
import json
import pathlib
import sys

destination, version, commit, target, arch, source_epoch, build_time, glibc_baseline = sys.argv[1:]
payload = {
    "format_version": 1,
    "product": "asl-client",
    "version": version,
    "git_commit": commit,
    "target": target,
    "architecture": arch,
    "source_date_epoch": int(source_epoch),
    "source_date": build_time,
    "glibc_baseline": glibc_baseline,
    "desktop": "eframe/egui",
}
pathlib.Path(destination).write_text(
    json.dumps(payload, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

{
  printf '%s\n' '# Ubuntu runtime packages required by the complete ASL client.'
  printf '%s\n' "${apt_packages[@]}"
  printf '\n'
  if [[ -n "$apt_deps_dir" ]]; then
    printf '%s\n' 'This archive includes matching .deb dependencies in payload/apt-deps.'
    printf '%s\n' 'Install them with: ./install.sh --install-system-dependencies'
  else
    printf '%s\n' 'This archive has no bundled system dependency .debs.'
    printf '%s\n' 'Install them online with: sudo ./install-deps.sh'
  fi
  printf '\n'
  printf '%s\n' 'The six ASL executables are inside this package. Rust, Cargo and a compiler'
  printf '%s\n' 'are not runtime requirements.'
} > "$package_root/APT-DEPENDENCIES.txt"
{
  printf '%s\n' '# Generated from packaging/linux/client/apt-packages.txt'
  printf '%s\n' "${apt_packages[@]}"
} > "$package_root/APT-PACKAGES.txt"

(
  cd "$package_root"
  find . -type f ! -name 'SHA256SUMS' -print0 \
    | sort -z \
    | xargs -0 sha256sum > SHA256SUMS
)

mkdir -p "$output_dir"
archive="$output_dir/$package_name.tar.gz"
archive_hash="$archive.sha256"
if [[ -e "$archive" || -e "$archive_hash" ]]; then
  printf 'Refusing to overwrite an existing client archive or sidecar: %s\n' "$archive" >&2
  exit 1
fi
temporary_archive="$output_dir/.$package_name.tar.gz.$$"
if [[ -e "$temporary_archive" ]]; then
  printf 'Temporary archive already exists: %s\n' "$temporary_archive" >&2
  exit 1
fi
temporary_paths+=("$temporary_archive")
tar \
  --sort=name \
  --mtime="@$release_epoch" \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  -cf - \
  -C "$stage" \
  "$package_name" | gzip -n > "$temporary_archive"
python3 "$repo/packaging/linux/client/release_archive.py" verify "$temporary_archive" >/dev/null
mv -- "$temporary_archive" "$archive"
(
  cd "$output_dir"
  sha256sum "$(basename "$archive")" > "$(basename "$archive_hash")"
)
printf '%s\n' "$archive"
printf '%s\n' "$archive_hash"

if (( build_deb )); then
  deb_name="asl-client_${version}_${deb_arch}.deb"
  deb="$output_dir/$deb_name"
  deb_hash="$deb.sha256"
  if [[ -e "$deb" || -e "$deb_hash" ]]; then
    printf 'Refusing to overwrite an existing deb or sidecar: %s\n' "$deb" >&2
    exit 1
  fi
  deb_root="$stage/deb-root"
  mkdir -p \
    "$deb_root/DEBIAN" \
    "$deb_root/opt/asl/bin" \
    "$deb_root/opt/asl/share/asl/config" \
    "$deb_root/opt/asl/share/asl/systemd" \
    "$deb_root/usr/bin" \
    "$deb_root/usr/share/applications" \
    "$deb_root/usr/share/icons/hicolor/scalable/apps" \
    "$deb_root/usr/share/icons/hicolor/256x256/apps" \
    "$deb_root/usr/lib/systemd/user" \
    "$deb_root/etc/xdg/asl" \
    "$deb_root/usr/share/doc/asl"

  for executable in "${executables[@]}"; do
    install -m 0755 "$payload/bin/$executable" "$deb_root/opt/asl/bin/$executable"
    ln -s "../../opt/asl/bin/$executable" "$deb_root/usr/bin/$executable"
  done

  escaped_replacement() {
    printf '%s' "$1" | sed 's/[\\&|]/\\&/g'
  }
  deb_prefix_escaped="$(escaped_replacement /opt/asl)"
  deb_config_escaped="$(escaped_replacement /etc/xdg/asl/asl.env)"
  deb_exec_escaped="$(escaped_replacement /usr/bin/asl-launch)"
  sed \
    -e "s|@PREFIX@|$deb_prefix_escaped|g" \
    -e "s|@CONFIG_FILE@|$deb_config_escaped|g" \
    "$payload/bin/asl-launch.in" > "$deb_root/opt/asl/bin/asl-launch"
  chmod 0755 "$deb_root/opt/asl/bin/asl-launch"
  ln -s "../../opt/asl/bin/asl-launch" "$deb_root/usr/bin/asl-launch"

  deb_service_exec_escaped="$(escaped_replacement /usr/bin/asl-core-service)"
  sed \
    -e "s|@PREFIX@|$deb_prefix_escaped|g" \
    -e "s|@CONFIG_FILE@|$deb_config_escaped|g" \
    "$payload/bin/asl-core-service.in" > "$deb_root/opt/asl/bin/asl-core-service"
  chmod 0755 "$deb_root/opt/asl/bin/asl-core-service"
  ln -s "../../opt/asl/bin/asl-core-service" "$deb_root/usr/bin/asl-core-service"

  sed \
    -e "s|@PREFIX@|$deb_prefix_escaped|g" \
    -e "s|@SERVICE_EXEC@|$deb_service_exec_escaped|g" \
    "$payload/systemd/asl-core.service.in" > "$deb_root/usr/lib/systemd/user/asl-core.service"
  chmod 0644 "$deb_root/usr/lib/systemd/user/asl-core.service"

  sed \
    -e "s|^Exec=asl-launch |Exec=$deb_exec_escaped |" \
    -e "s|^TryExec=asl-launch$|TryExec=$deb_exec_escaped|" \
    "$payload/share/applications/asl.desktop" > "$deb_root/usr/share/applications/asl.desktop"
  chmod 0644 "$deb_root/usr/share/applications/asl.desktop"
  install -m 0644 "$payload/share/icons/hicolor/scalable/apps/asl.svg" \
    "$deb_root/usr/share/icons/hicolor/scalable/apps/asl.svg"
  install -m 0644 "$payload/share/icons/hicolor/256x256/apps/asl.png" \
    "$deb_root/usr/share/icons/hicolor/256x256/apps/asl.png"
  install -m 0644 "$payload/config/asl.env.example" "$deb_root/etc/xdg/asl/asl.env"
  printf '/etc/xdg/asl/asl.env\n' > "$deb_root/DEBIAN/conffiles"

  for document in README.md LICENSE THIRD-PARTY.txt sbom.cdx.json MPL-SOURCES.zip \
    BUILD-INFO.json APT-DEPENDENCIES.txt APT-PACKAGES.txt install-deps.sh; do
    install -m 0644 "$package_root/$document" "$deb_root/usr/share/doc/asl/$document"
  done
  install -m 0644 "$package_root/LICENSE" "$deb_root/usr/share/doc/asl/copyright"
  (
    cd "$deb_root"
    find opt usr etc -type f ! -path 'usr/share/doc/asl/SHA256SUMS' -print0 \
      | sort -z \
      | xargs -0 sha256sum > usr/share/doc/asl/SHA256SUMS
  )

  installed_size="$(du -sk "$deb_root" | awk '{print $1}')"
  maintainer="${ASL_DEB_MAINTAINER:-ASL Project <noreply@localhost>}"
  deb_depends=""
  for package in "${apt_packages[@]}"; do
    rendered="$package"
    [[ "$package" == "libc6" ]] && rendered="libc6 (>= $glibc_baseline)"
    if [[ -n "$deb_depends" ]]; then
      deb_depends+=", "
    fi
    deb_depends+="$rendered"
  done
  depends="${ASL_DEB_DEPENDS:-$deb_depends}"
  {
    printf 'Package: asl-client\n'
    printf 'Version: %s\n' "$version"
    printf 'Architecture: %s\n' "$deb_arch"
    printf 'Maintainer: %s\n' "$maintainer"
    printf 'Installed-Size: %s\n' "$installed_size"
    printf 'Section: net\n'
    printf 'Priority: optional\n'
    printf 'Homepage: https://github.com/superalp1985/asl-agents-letters\n'
    printf 'Depends: %s\n' "$depends"
    printf 'Recommends: systemd\n'
    printf 'Description: ASL decentralized agent client\n'
    printf ' ASL provides authorized peer-to-peer agent messaging, groups and file\n'
    printf ' transfer with libp2p, MLS and chain-backed identity verification.\n'
  } > "$deb_root/DEBIAN/control"

  cat > "$deb_root/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database -q /usr/share/applications >/dev/null 2>&1 || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -q /usr/share/icons/hicolor >/dev/null 2>&1 || true
fi
exit 0
EOF
  cat > "$deb_root/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database -q /usr/share/applications >/dev/null 2>&1 || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -q /usr/share/icons/hicolor >/dev/null 2>&1 || true
fi
exit 0
EOF
  chmod 0755 "$deb_root/DEBIAN/postinst" "$deb_root/DEBIAN/postrm"

  temporary_deb="$output_dir/.$deb_name.$$"
  if [[ -e "$temporary_deb" ]]; then
    printf 'Temporary deb already exists: %s\n' "$temporary_deb" >&2
    exit 1
  fi
  temporary_paths+=("$temporary_deb")
  SOURCE_DATE_EPOCH="$release_epoch" dpkg-deb \
    --root-owner-group \
    --build \
    "$deb_root" \
    "$temporary_deb" >/dev/null
  dpkg-deb --info "$temporary_deb" >/dev/null
  deb_contents="$(dpkg-deb --contents "$temporary_deb")"
  grep -Fq './opt/asl/bin/asl-ui' <<<"$deb_contents"
  grep -Fq './opt/asl/bin/asl-core-service' <<<"$deb_contents"
  grep -Fq './usr/share/applications/asl.desktop' <<<"$deb_contents"
  deb_check_root="$stage/deb-check"
  dpkg-deb --extract "$temporary_deb" "$deb_check_root"
  (
    cd "$deb_check_root"
    sha256sum -c usr/share/doc/asl/SHA256SUMS >/dev/null
  )
  mv -- "$temporary_deb" "$deb"
  (
    cd "$output_dir"
    sha256sum "$(basename "$deb")" > "$(basename "$deb_hash")"
  )
  printf '%s\n' "$deb"
  printf '%s\n' "$deb_hash"
fi
