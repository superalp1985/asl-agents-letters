#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 022

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${1:-$repo/target/release-packages}"
metadata_args=(metadata --manifest-path "$repo/Cargo.toml" --no-deps --format-version 1 --locked)
offline_args=()
if [[ "${ASL_CARGO_OFFLINE:-0}" == "1" ]]; then
  metadata_args+=(--offline)
  offline_args+=(--offline)
fi
metadata="$(cargo "${metadata_args[@]}")"
version="$(python3 -c 'import json,sys; data=json.load(sys.stdin); print(next(p["version"] for p in data["packages"] if p["name"]=="asl-app"))' <<<"$metadata")"
target_dir="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])' <<<"$metadata")"
host_target="$(rustc -vV | sed -n 's/^host: //p')"
target="${ASL_INFRA_TARGET:-$host_target}"
case "$target" in
  x86_64-*-linux-*) arch=x86_64 ;;
  aarch64-*-linux-*) arch=aarch64 ;;
  *)
    printf 'Supported Linux release targets must be x86_64 or aarch64 Linux triples.\n' >&2
    exit 1
    ;;
esac
if [[ -n "${ASL_INFRA_ARCH:-}" && "$ASL_INFRA_ARCH" != "$arch" ]]; then
  printf 'ASL_INFRA_ARCH does not match ASL_INFRA_TARGET.\n' >&2
  exit 1
fi
if [[ ! "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  printf 'Linux releases require a stable X.Y.Z version.\n' >&2
  exit 1
fi
release_epoch="${SOURCE_DATE_EPOCH:-$(git -C "$repo" show -s --format=%ct HEAD)}"
if [[ ! "$release_epoch" =~ ^(0|[1-9][0-9]{0,11})$ ]] \
  || (( release_epoch < 315532800 || release_epoch > 4354819198 )); then
  printf 'SOURCE_DATE_EPOCH must fit the deterministic ZIP/tar timestamp range.\n' >&2
  exit 1
fi
commit="$(git -C "$repo" rev-parse HEAD)"
build_time="$(date -u -d "@$release_epoch" +%Y-%m-%dT%H:%M:%SZ)"

if [[ "${ASL_RELEASE_ALLOW_DIRTY:-0}" != "1" && -n "$(git -C "$repo" status --porcelain --untracked-files=normal)" ]]; then
  printf 'Refusing an official package from a dirty worktree. Set ASL_RELEASE_ALLOW_DIRTY=1 only for local builds.\n' >&2
  exit 1
fi

stage="$(mktemp -d)"
temporary_archive=""
release_complete=0
trap 'rm -rf "$stage"; [[ -z "$temporary_archive" ]] || rm -f -- "$temporary_archive"; if (( ! release_complete )); then [[ -z "${archive:-}" ]] || rm -f -- "$archive"; [[ -z "${hash_sidecar:-}" ]] || rm -f -- "$hash_sidecar"; fi' EXIT

mkdir -p "$out"
build_args=(build \
  --manifest-path "$repo/Cargo.toml" \
  -p asl-app \
  --bin asl-infra \
  --release \
  --locked)
if [[ "$target" != "$host_target" ]]; then
  build_args+=(--target "$target")
fi
build_args+=("${offline_args[@]}")
cargo "${build_args[@]}"

package_name="asl-infra-linux-$arch-$version"
package_root="$stage/$package_name"
binary_dir="$target_dir/release"
if [[ "$target" != "$host_target" ]]; then
  binary_dir="$target_dir/$target/release"
fi
install -d -m 0755 "$package_root"
install -m 0755 "$binary_dir/asl-infra" "$package_root/asl-infra"
install -m 0644 "$repo/packaging/linux/asl-infra.service.in" "$package_root/asl-infra.service.in"
install -m 0644 "$repo/specs/infra.example.toml" "$package_root/infra.example.toml"
for tool in install.sh upgrade.sh rollback.sh release-common.sh verify-release.sh \
  verify-offline-release.sh release_archive.py; do
  install -m 0755 "$repo/packaging/linux/$tool" "$package_root/$tool"
done
install -m 0644 "$repo/packaging/linux/README.md" "$package_root/README.md"
install -m 0644 "$repo/LICENSE" "$package_root/LICENSE"

notice_args=(
  "$repo/scripts/package-linux-notices.py"
  --repo "$repo"
  --output "$package_root"
  --target "$target"
  --version "$version"
  --source-date-epoch "$release_epoch"
)
if [[ "${ASL_CARGO_OFFLINE:-0}" == "1" ]]; then
  notice_args+=(--offline)
fi
python3 "${notice_args[@]}"

python3 - "$package_root/BUILD-INFO.json" "$version" "$commit" "$target" "$arch" "$release_epoch" "$build_time" <<'PY'
import json
import pathlib
import sys

destination, version, commit, target, arch, release_epoch, source_date = sys.argv[1:]
payload = {
    "format_version": 1,
    "product": "asl-infra",
    "version": version,
    "git_commit": commit,
    "target": target,
    "architecture": arch,
    "source_date_epoch": int(release_epoch),
    "source_date": source_date,
}
pathlib.Path(destination).write_text(
    json.dumps(payload, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

(
  cd "$package_root"
  find . -type f ! -name 'SHA256SUMS' -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)

archive="$out/$package_name.tar.gz"
hash_sidecar="$archive.sha256"
if [[ -e "$archive" || -e "$hash_sidecar" ]]; then
  printf 'Refusing to overwrite an existing Linux release artifact or hash sidecar.\n' >&2
  exit 1
fi
temporary_archive="$out/.$package_name.tar.gz.$$"
if [[ -e "$temporary_archive" ]]; then
  printf 'Temporary release artifact already exists: %s\n' "$temporary_archive" >&2
  exit 1
fi
tar \
  --sort=name \
  --mtime="@$release_epoch" \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  -cf - \
  -C "$stage" \
  "$package_name" | gzip -n > "$temporary_archive"
mv -- "$temporary_archive" "$archive"

(
  cd "$out"
  sha256sum "$(basename "$archive")" > "$(basename "$hash_sidecar")"
)
release_complete=1

printf '%s\n' "$archive"
printf '%s\n' "$archive.sha256"
