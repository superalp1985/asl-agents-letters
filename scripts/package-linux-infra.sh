#!/usr/bin/env bash
set -euo pipefail

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
arch="${ASL_INFRA_ARCH:-$(uname -m)}"
release_epoch="${SOURCE_DATE_EPOCH:-$(git -C "$repo" show -s --format=%ct HEAD)}"
commit="$(git -C "$repo" rev-parse HEAD)"
build_time="$(date -u -d "@$release_epoch" +%Y-%m-%dT%H:%M:%SZ)"

if [[ "${ASL_RELEASE_ALLOW_DIRTY:-0}" != "1" && -n "$(git -C "$repo" status --porcelain --untracked-files=normal)" ]]; then
  printf 'Refusing an official package from a dirty worktree. Set ASL_RELEASE_ALLOW_DIRTY=1 only for local builds.\n' >&2
  exit 1
fi

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

mkdir -p "$out"
cargo build \
  --manifest-path "$repo/Cargo.toml" \
  -p asl-app \
  --bin asl-infra \
  --release \
  --locked \
  "${offline_args[@]}"

package_name="asl-infra-linux-$arch-$version"
package_root="$stage/$package_name"
install -d -m 0755 "$package_root"
install -m 0755 "$target_dir/release/asl-infra" "$package_root/asl-infra"
install -m 0644 "$repo/packaging/linux/asl-infra.service.in" "$package_root/asl-infra.service.in"
install -m 0644 "$repo/specs/infra.example.toml" "$package_root/infra.example.toml"
install -m 0755 "$repo/packaging/linux/install.sh" "$package_root/install.sh"
install -m 0644 "$repo/packaging/linux/README.md" "$package_root/README.md"
install -m 0644 "$repo/LICENSE" "$package_root/LICENSE"

notice_args=(
  "$repo/scripts/package-linux-notices.py"
  --repo "$repo"
  --output "$package_root"
  --target "${ASL_INFRA_TARGET:-$(rustc -vV | sed -n 's/^host: //p')}"
  --version "$version"
)
if [[ "${ASL_CARGO_OFFLINE:-0}" == "1" ]]; then
  notice_args+=(--offline)
fi
python3 "${notice_args[@]}"

python3 - "$package_root/BUILD-INFO.json" "$version" "$commit" "${ASL_INFRA_TARGET:-$(rustc -vV | sed -n 's/^host: //p')}" "$arch" "$release_epoch" "$build_time" <<'PY'
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
tar \
  --sort=name \
  --mtime="@$release_epoch" \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  -czf "$archive" \
  -C "$stage" \
  "$package_name"

(
  cd "$out"
  sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256"
)

printf '%s\n' "$archive"
printf '%s\n' "$archive.sha256"
