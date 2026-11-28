#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

package_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
script_dir="$package_root"
. "$script_dir/client-common.sh"

usage() {
  cat <<'EOF'
Usage: ./install.sh [options]

Install the ASL Linux desktop client without requiring Rust. The default
per-user prefix is $HOME/.local and the default ASL_HOME is
$XDG_DATA_HOME/asl (or $HOME/.local/share/asl).

Options:
  --prefix DIR             Installation prefix
  --asl-home DIR           Absolute ASL profile/data directory
  --enable-user-service    Install, enable and start the systemd --user unit
  --no-start               Enable but do not start the user service
  --install-system-dependencies
                           Install bundled offline .deb dependencies, or use APT online
  --skip-profile-init      Do not initialize an absent ASL profile
  --no-desktop             Do not install the desktop file or icons
  --upgrade                Require an existing managed installation
  -h, --help               Show this help
EOF
}

prefix=""
asl_home=""
enable_service=0
start_service=1
initialize_profile=1
install_desktop=1
upgrade=0
install_system_dependencies=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      prefix="$2"
      shift 2
      ;;
    --asl-home)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      asl_home="$2"
      shift 2
      ;;
    --enable-user-service)
      enable_service=1
      shift
      ;;
    --no-start)
      start_service=0
      shift
      ;;
    --install-system-dependencies)
      install_system_dependencies=1
      shift
      ;;
    --skip-profile-init)
      initialize_profile=0
      shift
      ;;
    --no-desktop)
      install_desktop=0
      shift
      ;;
    --upgrade)
      upgrade=1
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

for required_command in \
  awk cmp grep install ldd paste python3 readlink realpath sed sha256sum; do
  command -v "$required_command" >/dev/null 2>&1 || {
    printf 'Required system command is missing: %s\n' "$required_command" >&2
    exit 1
  }
done

prefix="${prefix:-${ASL_CLIENT_PREFIX:-$HOME/.local}}"
asl_client_validate_path "$prefix" 'Install prefix'
prefix="$(realpath -m -- "$prefix")"
[[ "$prefix" != "/" ]] || asl_client_die "Refusing to install directly into /"

layout_file="$prefix/lib/asl/install-layout.conf"
if [[ -L "$layout_file" ]]; then
  asl_client_die "Installed layout must not be a symlink: $layout_file"
fi
if [[ -e "$layout_file" && ! -f "$layout_file" ]]; then
  asl_client_die "Installed layout must be a regular file: $layout_file"
fi
had_layout=0
if [[ -f "$layout_file" ]]; then
  had_layout=1
  asl_client_load_layout "$layout_file"
  [[ "$asl_client_prefix" == "$prefix" ]] \
    || asl_client_die "Persisted layout uses a different prefix: $asl_client_prefix"
  if [[ -n "$asl_home" && "$asl_home" != "$asl_client_home" ]]; then
    asl_client_die "Changing ASL_HOME during upgrade is not automatic; migrate the profile explicitly."
  fi
  asl_home="$asl_client_home"
elif (( upgrade )); then
  asl_client_die "--upgrade requires an existing installation under $prefix"
fi

asl_home="${asl_home:-${XDG_DATA_HOME:-$HOME/.local/share}/asl}"
asl_client_validate_path "$asl_home" 'ASL_HOME'
asl_home="$(realpath -m -- "$asl_home")"
case "$asl_home" in
  /|"$HOME")
    asl_client_die "Refusing unsafe ASL_HOME: $asl_home"
    ;;
esac

required=(
  BUILD-INFO.json SHA256SUMS README.md LICENSE THIRD-PARTY.txt sbom.cdx.json
  MPL-SOURCES.zip APT-DEPENDENCIES.txt APT-PACKAGES.txt install-deps.sh
  client-common.sh uninstall.sh upgrade.sh verify.sh release_archive.py
  payload/bin/asl payload/bin/asl-core payload/bin/asl-net
  payload/bin/asl-worker payload/bin/asl-extractor payload/bin/asl-ui
  payload/bin/asl-launch.in payload/bin/asl-core-service.in
  payload/share/applications/asl.desktop
  payload/share/icons/hicolor/scalable/apps/asl.svg
  payload/share/icons/hicolor/256x256/apps/asl.png
  payload/config/asl.env.example payload/systemd/asl-core.service.in
)
for required_file in "${required[@]}"; do
  [[ -f "$package_root/$required_file" && ! -L "$package_root/$required_file" ]] \
    || asl_client_die "Package member is missing or unsafe: $required_file"
done
(
  cd "$package_root"
  sha256sum -c SHA256SUMS >/dev/null
)
if (( install_system_dependencies )); then
  bash "$package_root/install-deps.sh"
fi
asl_client_check_binary_dependencies "$package_root/payload/bin"

if (( ! had_layout )); then
  for path in "$prefix/bin" "$prefix/lib/asl" "$prefix/libexec/asl"; do
    if [[ -e "$path" || -L "$path" ]]; then
      [[ -d "$path" && ! -L "$path" ]] \
        || asl_client_die "Existing installation path is not a real directory: $path"
    fi
  done
fi

release_root="$prefix/lib/asl/releases"
tools_dir="$prefix/libexec/asl"
desktop_dir="$prefix/share/applications"
icon_root="$prefix/share/icons/hicolor"
service_dir="$prefix/lib/systemd/user"
install -d -m 0755 \
  "$prefix/bin" "$release_root" "$tools_dir" "$desktop_dir" "$icon_root" \
  "$service_dir" "$prefix/etc/asl"

mkdir -p "$asl_home"
chmod 0700 "$asl_home"
if (( initialize_profile )) && [[ ! -f "$asl_home/state/asl.sqlite3" ]]; then
  initialization_log="$(mktemp)"
  if ! ASL_HOME="$asl_home" "$package_root/payload/bin/asl-core" \
    --initialize-profile --json >"$initialization_log" 2>&1; then
    cat "$initialization_log" >&2
    rm -f -- "$initialization_log"
    asl_client_die "ASL profile initialization failed for $asl_home"
  fi
  rm -f -- "$initialization_log"
  printf 'Initialized ASL profile: %s\n' "$asl_home"
elif [[ -f "$asl_home/state/asl.sqlite3" ]]; then
  printf 'Preserved existing ASL profile: %s\n' "$asl_home"
fi

version="$(
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["version"])' \
    "$package_root/BUILD-INFO.json"
)"
content_hash="$(
  cd "$package_root/payload/bin"
  sha256sum asl asl-core asl-net asl-worker asl-extractor asl-ui \
    | sha256sum \
    | awk '{print $1}'
)"
release_id="release-$version-${content_hash:0:16}"
release_dir="$release_root/$release_id"
current_path="$release_root/current"

for executable in asl asl-core asl-net asl-worker asl-extractor asl-ui; do
  launcher="$prefix/bin/$executable"
  if [[ -e "$launcher" || -L "$launcher" ]]; then
    asl_client_managed_symlink "$launcher" "$current_path/bin/$executable" \
      || asl_client_die "Refusing to replace an unmanaged launcher: $launcher"
  fi
done
launch_path="$prefix/bin/asl-launch"
if [[ -e "$launch_path" || -L "$launch_path" ]]; then
  asl_client_managed_symlink "$launch_path" "$tools_dir/asl-launch" \
    || asl_client_die "Refusing to replace an unmanaged launcher: $launch_path"
fi
service_launcher="$prefix/bin/asl-core-service"
if [[ -e "$service_launcher" || -L "$service_launcher" ]]; then
  asl_client_managed_symlink "$service_launcher" "$tools_dir/asl-core-service" \
    || asl_client_die "Refusing to replace an unmanaged service launcher: $service_launcher"
fi

created_release=0
install_complete=0
cleanup_install() {
  local status=$?
  trap - EXIT
  if (( ! install_complete && created_release )); then
    current_target="$(readlink -- "$current_path" 2>/dev/null || true)"
    if [[ "$current_target" != "$release_id" ]]; then
      rm -rf -- "$release_dir"
    fi
  fi
  exit "$status"
}
trap cleanup_install EXIT
if [[ -e "$release_dir" || -L "$release_dir" ]]; then
  [[ -d "$release_dir" && ! -L "$release_dir" ]] \
    || asl_client_die "Release path is unsafe: $release_dir"
  for executable in asl asl-core asl-net asl-worker asl-extractor asl-ui; do
    cmp -s "$package_root/payload/bin/$executable" "$release_dir/bin/$executable" \
      || asl_client_die "Existing release content differs from the verified package: $release_id"
  done
else
  install -d -m 0755 "$release_dir/bin"
  created_release=1
  for executable in asl asl-core asl-net asl-worker asl-extractor asl-ui; do
    install -m 0755 "$package_root/payload/bin/$executable" "$release_dir/bin/$executable"
  done
  install -m 0644 "$package_root/BUILD-INFO.json" "$release_dir/BUILD-INFO.json"
fi

for tool in install.sh uninstall.sh upgrade.sh verify.sh client-common.sh release_archive.py; do
  install -m 0755 "$package_root/$tool" "$tools_dir/$tool"
done

prefix_escaped="$(asl_client_sed_escape "$prefix")"
config_path="$prefix/etc/asl/asl.env"
config_escaped="$(asl_client_sed_escape "$config_path")"
temporary_launcher="$tools_dir/.asl-launch.$$"
sed \
  -e "s|@PREFIX@|$prefix_escaped|g" \
  -e "s|@CONFIG_FILE@|$config_escaped|g" \
  "$package_root/payload/bin/asl-launch.in" > "$temporary_launcher"
chmod 0755 "$temporary_launcher"
mv -Tf -- "$temporary_launcher" "$tools_dir/asl-launch"

temporary_core_service="$tools_dir/.asl-core-service.$$"
sed \
  -e "s|@PREFIX@|$prefix_escaped|g" \
  -e "s|@CONFIG_FILE@|$config_escaped|g" \
  "$package_root/payload/bin/asl-core-service.in" > "$temporary_core_service"
chmod 0755 "$temporary_core_service"
mv -Tf -- "$temporary_core_service" "$tools_dir/asl-core-service"

service_template="$package_root/payload/systemd/asl-core.service.in"
temporary_service="$service_dir/.asl-core.service.$$"
service_exec_escaped="$(asl_client_sed_escape "$service_launcher")"
sed \
  -e "s|@PREFIX@|$prefix_escaped|g" \
  -e "s|@SERVICE_EXEC@|$service_exec_escaped|g" \
  "$service_template" > "$temporary_service"
chmod 0644 "$temporary_service"
mv -Tf -- "$temporary_service" "$service_dir/asl-core.service"

if (( ! had_layout )); then
  asl_client_prefix="$prefix"
  asl_release_root="$release_root"
  asl_tools_dir="$tools_dir"
  asl_desktop_dir="$desktop_dir"
  asl_icon_root="$icon_root"
  asl_service_dir="$service_dir"
  asl_client_write_layout "$layout_file"
fi

temporary_current="$release_root/.current.$$"
ln -s -- "$release_id" "$temporary_current"
mv -Tf -- "$temporary_current" "$current_path"

for executable in asl asl-core asl-net asl-worker asl-extractor asl-ui; do
  ln -sfn -- "$current_path/bin/$executable" "$prefix/bin/$executable"
done
ln -sfn -- "$tools_dir/asl-launch" "$launch_path"
ln -sfn -- "$tools_dir/asl-core-service" "$service_launcher"

if [[ ! -e "$config_path" ]]; then
  {
    printf '# Generated by the ASL client installer. Edit ASL_HOME if needed.\n'
    printf 'ASL_HOME=%q\n' "$asl_home"
  } > "$config_path"
  chmod 0644 "$config_path"
fi

if (( install_desktop )); then
  desktop_exec="$(asl_client_desktop_quote "$launch_path")"
  desktop_exec_escaped="$(asl_client_sed_escape "$desktop_exec")"
  temporary_desktop="$desktop_dir/.asl.desktop.$$"
  sed \
    -e "s|^Exec=.*|Exec=$desktop_exec_escaped %U|" \
    -e "s|^TryExec=.*|TryExec=$prefix_escaped/bin/asl-launch|" \
    "$package_root/payload/share/applications/asl.desktop" > "$temporary_desktop"
  chmod 0644 "$temporary_desktop"
  mv -Tf -- "$temporary_desktop" "$desktop_dir/asl.desktop"
  install -d -m 0755 \
    "$icon_root/scalable/apps" "$icon_root/256x256/apps"
  install -m 0644 "$package_root/payload/share/icons/hicolor/scalable/apps/asl.svg" \
    "$icon_root/scalable/apps/asl.svg"
  install -m 0644 "$package_root/payload/share/icons/hicolor/256x256/apps/asl.png" \
    "$icon_root/256x256/apps/asl.png"
  if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q "$desktop_dir" >/dev/null 2>&1 || true
  fi
  if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -q "$icon_root" >/dev/null 2>&1 || true
  fi
fi

doc_dir="$prefix/share/doc/asl"
install -d -m 0755 "$doc_dir"
for document in README.md LICENSE THIRD-PARTY.txt sbom.cdx.json MPL-SOURCES.zip \
  BUILD-INFO.json APT-DEPENDENCIES.txt APT-PACKAGES.txt; do
  install -m 0644 "$package_root/$document" "$doc_dir/$document"
done
install -m 0755 "$package_root/install-deps.sh" "$doc_dir/install-deps.sh"

user_unit_dir="$(asl_client_user_unit_dir)"
user_unit="$user_unit_dir/asl-core.service"
managed_user_service=0
service_was_active=0
if [[ -f "$user_unit" && ! -L "$user_unit" ]]; then
  if grep -Fqx "ExecStart=$prefix/bin/asl-core-service" "$user_unit"; then
    managed_user_service=1
    if command -v systemctl >/dev/null 2>&1 \
      && systemctl --user is-active --quiet asl-core.service; then
      service_was_active=1
    fi
  elif (( enable_service )); then
    asl_client_die "Refusing to replace an unmanaged user service: $user_unit"
  fi
fi

if (( enable_service )); then
  command -v systemctl >/dev/null 2>&1 \
    || asl_client_die "--enable-user-service requires systemd"
  install -d -m 0755 "$user_unit_dir"
  install -m 0644 "$service_dir/asl-core.service" "$user_unit"
  managed_user_service=1
  systemctl --user daemon-reload
  systemctl --user enable asl-core.service >/dev/null
  if (( start_service )); then
    systemctl --user restart asl-core.service
  fi
elif (( managed_user_service && service_was_active )); then
  systemctl --user daemon-reload
  systemctl --user restart asl-core.service
fi

install_complete=1
printf '\nInstalled ASL client.\n'
printf 'Prefix:   %s\n' "$prefix"
printf 'ASL_HOME: %s\n' "$asl_home"
printf 'Launch:   %s\n' "$launch_path"
printf 'Release:  %s\n' "$release_id"
printf 'Upgrade:  %s/upgrade.sh <asl-client-linux-*.tar.gz>\n' "$tools_dir"
printf 'Uninstall: %s/uninstall.sh\n' "$tools_dir"
if (( ! enable_service )); then
  printf 'The desktop launcher starts Core in the background when no user service is enabled.\n'
fi
