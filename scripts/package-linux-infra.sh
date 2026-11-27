#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${1:-$repo/../dist}"
version="$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["packages"][0]["version"])')"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

mkdir -p "$out"
cargo build -p asl-app --bin asl-infra --release --locked
install -Dm755 "$repo/target/release/asl-infra" "$stage/asl-infra"
install -Dm644 "$repo/packaging/linux/asl-infra.service" "$stage/asl-infra.service"
install -Dm600 "$repo/specs/infra.example.toml" "$stage/infra.example.toml"

cat > "$stage/install.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
root="${1:-/opt/asl-infra}"
user="${2:-asl-infra}"
if ! id "$user" >/dev/null 2>&1; then
  useradd --system --home "$root" --shell /usr/sbin/nologin "$user"
fi
install -d -m 700 "$root"
install -m 755 ./asl-infra "$root/asl-infra"
install -m 644 ./asl-infra.service /etc/systemd/system/asl-infra.service
if [ ! -f "$root/infra.toml" ]; then
  install -m 600 ./infra.example.toml "$root/infra.toml"
fi
chown -R "$user:$user" "$root"
systemctl daemon-reload
echo "Install complete. Review $root/infra.toml, then: systemctl enable --now asl-infra"
EOF

chmod 755 "$stage/install.sh"
(
  cd "$stage"
  find . -type f ! -name 'SHA256SUMS' -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
  tar --sort=name --mtime='UTC 2026-01-01' --owner=0 --group=0 --numeric-owner -czf "$out/asl-infra-linux-x86_64-$version.tar.gz" .
)
echo "$out/asl-infra-linux-x86_64-$version.tar.gz"
