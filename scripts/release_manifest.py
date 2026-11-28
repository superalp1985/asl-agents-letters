#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from release_tools.manifest import (  # noqa: E402
    FORMAT_VERSION,
    PRODUCT,
    ReleaseError,
    asset_record,
    canonical_json,
    generate_private_key,
    load_private_key,
    load_public_key,
    private_key_pem,
    public_key_document,
    sign_manifest,
    validate_manifest,
    verify_manifest,
)


def write_new(path: Path, data: bytes, mode: int = 0o644) -> None:
    if path.exists() or path.is_symlink():
        raise ReleaseError(f"refusing to overwrite: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)
    try:
        path.chmod(mode)
    except OSError:
        pass


def keygen(args: argparse.Namespace) -> int:
    private_path = args.private_key.resolve()
    public_path = args.public_key.resolve()
    repo = REPO.resolve()
    if repo == private_path or repo in private_path.parents:
        raise ReleaseError("release private key must stay outside the repository")
    if private_path.exists() or public_path.exists():
        raise ReleaseError("key output already exists")
    private = generate_private_key()
    public = public_key_document(private.public_key())
    write_new(private_path, private_key_pem(private), 0o600)
    write_new(
        public_path,
        (json.dumps(public, indent=2, sort_keys=True) + "\n").encode("ascii"),
    )
    print(f"Public-key SHA-256: {public['fingerprint_sha256']}")
    return 0


def infer_asset(name: str, distribution: str) -> tuple[str, str, str, str]:
    lowered = name.lower()
    arch = "aarch64" if "aarch64" in lowered or "arm64" in lowered else "x86_64"
    if lowered.startswith("asl-bootstrap-windows-") and lowered.endswith((".ps1", ".exe")):
        return "windows", arch, "windows", "bootstrap"
    if lowered.startswith("asl-bootstrap-linux-"):
        return "linux", arch, distribution, "bootstrap"
    if lowered.startswith("asl-windows-") and lowered.endswith(".zip"):
        return "windows", arch, "windows", "client"
    if lowered.startswith("asl-client-linux-") and lowered.endswith(".tar.gz"):
        return "linux", arch, distribution, "client"
    if lowered.startswith("asl-client_") and lowered.endswith(".deb"):
        return "linux", arch, distribution, "deb"
    raise ReleaseError(f"cannot infer platform metadata for asset: {name}")


def create(args: argparse.Namespace) -> int:
    private = load_private_key(args.private_key.resolve())
    assets = []
    for raw_path in args.asset:
        path = Path(raw_path).resolve()
        if not path.is_file() or path.is_symlink():
            raise ReleaseError(f"release asset is not a regular file: {path}")
        os_name, arch, distribution, kind = infer_asset(path.name, args.distribution)
        assets.append(
            asset_record(
                path,
                os_name=os_name,
                arch=arch,
                distribution=distribution,
                kind=kind,
            )
        )
    assets.sort(key=lambda item: (item["os"], item["arch"], item["kind"], item["name"]))
    document = {
        "assets": assets,
        "commit": args.commit,
        "format_version": FORMAT_VERSION,
        "generated_at": args.generated_at
        or dt.datetime.now(dt.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "product": PRODUCT,
        "tag": args.tag,
        "version": args.version,
    }
    validate_manifest(document)
    manifest = canonical_json(document)
    signature = sign_manifest(private, manifest)
    public = load_public_key(
        json.loads(args.public_key.read_text(encoding="utf-8"))
    )
    verify_manifest(public, manifest, signature)
    write_new(args.output, manifest)
    try:
        write_new(Path(str(args.output) + ".sig"), signature)
    except Exception:
        args.output.unlink(missing_ok=True)
        raise
    print(args.output)
    print(str(args.output) + ".sig")
    return 0


def verify(args: argparse.Namespace) -> int:
    public = load_public_key(json.loads(args.public_key.read_text(encoding="utf-8")))
    document = verify_manifest(
        public,
        args.manifest.read_bytes(),
        args.signature.read_bytes(),
    )
    print(
        f"Verified ASL release manifest: {document['tag']} "
        f"{document['version']} ({len(document['assets'])} assets)"
    )
    return 0


def export_bootstrap_key(args: argparse.Namespace) -> int:
    document = json.loads(args.public_key.read_text(encoding="utf-8"))
    load_public_key(document)
    rendered = (
        '"""Generated release verification key. Do not edit manually."""\n\n'
        f"PUBLIC_KEY = {document!r}\n"
    )
    if args.output.exists() or args.output.is_symlink():
        raise ReleaseError(f"refusing to overwrite: {args.output}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="ascii")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)

    keygen_parser = commands.add_parser("keygen")
    keygen_parser.add_argument("--private-key", type=Path, required=True)
    keygen_parser.add_argument("--public-key", type=Path, required=True)
    keygen_parser.set_defaults(function=keygen)

    create_parser = commands.add_parser("create")
    create_parser.add_argument("--private-key", type=Path, required=True)
    create_parser.add_argument("--public-key", type=Path, required=True)
    create_parser.add_argument("--tag", required=True)
    create_parser.add_argument("--version", required=True)
    create_parser.add_argument("--commit", required=True)
    create_parser.add_argument("--distribution", default="ubuntu-22.04")
    create_parser.add_argument("--generated-at")
    create_parser.add_argument("--output", type=Path, required=True)
    create_parser.add_argument("--asset", action="append", required=True)
    create_parser.set_defaults(function=create)

    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("--public-key", type=Path, required=True)
    verify_parser.add_argument("--manifest", type=Path, required=True)
    verify_parser.add_argument("--signature", type=Path, required=True)
    verify_parser.set_defaults(function=verify)

    export_parser = commands.add_parser("export-bootstrap-key")
    export_parser.add_argument("--public-key", type=Path, required=True)
    export_parser.add_argument("--output", type=Path, required=True)
    export_parser.set_defaults(function=export_bootstrap_key)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        return args.function(args)
    except (OSError, ValueError, ReleaseError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
