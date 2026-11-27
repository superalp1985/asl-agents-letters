#!/usr/bin/env python3
"""Generate Linux package notices, an MPL source offer, and a CycloneDX SBOM."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

NOTICE_NAME = re.compile(r"^(LICENSE|LICENCE|COPYING|NOTICE|COPYRIGHT)([-._]|$)")
MAX_NOTICE_BYTES = 256 * 1024


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--offline", action="store_true")
    return parser.parse_args()


def cargo_metadata(repo: Path, target: str, offline: bool) -> dict:
    command = [
        "cargo",
        "metadata",
        "--format-version",
        "1",
        "--locked",
        "--filter-platform",
        target,
        "--manifest-path",
        str(repo / "crates" / "asl-app" / "Cargo.toml"),
    ]
    if offline:
        command.append("--offline")
    output = subprocess.run(
        command,
        cwd=repo,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout
    return json.loads(output)


def runtime_packages(details: dict, repo: Path) -> tuple[dict, list[dict]]:
    packages = {package["id"]: package for package in details["packages"]}
    nodes = {node["id"]: node for node in details["resolve"]["nodes"]}
    manifest = (repo / "crates" / "asl-app" / "Cargo.toml").resolve()
    application = next(
        package
        for package in details["packages"]
        if Path(package["manifest_path"]).resolve() == manifest
    )

    selected: dict[str, dict] = {}
    pending = [application["id"]]
    while pending:
        package_id = pending.pop()
        if package_id in selected:
            continue
        selected[package_id] = packages[package_id]
        for dependency in nodes[package_id].get("deps", []):
            if any(kind.get("kind") is None for kind in dependency.get("dep_kinds", [])):
                pending.append(dependency["pkg"])

    ordered = sorted(selected.values(), key=lambda package: (package["name"], package["version"]))
    return application, ordered


def notice_files(package: dict) -> list[Path]:
    directory = Path(package["manifest_path"]).parent
    return sorted(
        (
            path
            for path in directory.iterdir()
            if path.is_file() and NOTICE_NAME.match(path.name)
        ),
        key=lambda path: path.name,
    )


def find_mpl_source(package: dict) -> Path:
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    filename = f'{package["name"]}-{package["version"]}.crate'
    cache = cargo_home / "registry" / "cache"
    matches = sorted(cache.glob(f"*/{filename}")) if cache.is_dir() else []
    if not matches:
        raise RuntimeError(f'MPL source archive not found in Cargo cache: {filename}')
    return matches[0]


def add_license_text(lines: list[str], package: dict, seen: set[str]) -> None:
    for path in notice_files(package):
        key = f'{package["name"]}:{package["version"]}:{path.name}'
        if key in seen:
            continue
        seen.add(key)
        if path.stat().st_size > MAX_NOTICE_BYTES:
            raise RuntimeError(f"Oversized license notice: {path}")
        lines.extend(["", path.name, path.read_text(encoding="utf-8", errors="replace")])


def main() -> int:
    args = parse_args()
    repo = args.repo.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)

    details = cargo_metadata(repo, args.target, args.offline)
    application, packages = runtime_packages(details, repo)
    if application["version"] != args.version:
        raise RuntimeError("Cargo metadata version does not match the requested package version.")

    lines = [
        "ASL Linux infrastructure runtime dependencies",
        "ASL project code is licensed under the repository MIT license.",
        "MPL-SOURCES.zip contains original crate archives for MPL-2.0 components.",
    ]
    seen_notices: set[str] = set()
    components: list[dict] = []
    mpl_sources: list[Path] = []

    for package in packages:
        if package["id"] == application["id"]:
            continue
        license_expression = package.get("license") or "NOASSERTION"
        lines.extend(
            [
                "",
                f'{package["name"]} {package["version"]} | {license_expression}',
            ]
        )
        if package.get("repository"):
            lines.append(package["repository"])

        component = {
            "type": "library",
            "name": package["name"],
            "version": package["version"],
        }
        if package.get("license"):
            component["licenses"] = [{"expression": package["license"]}]
        if package.get("source", "").startswith("registry+"):
            component["purl"] = f'pkg:cargo/{package["name"]}@{package["version"]}'
        if package.get("checksum"):
            component["hashes"] = [
                {"alg": "SHA-256", "content": package["checksum"]}
            ]
        components.append(component)

        add_license_text(lines, package, seen_notices)
        if re.search(r"\bMPL-2\.0\b", package.get("license") or ""):
            mpl_sources.append(find_mpl_source(package))

    licenses = repo / "docs" / "licenses"
    if licenses.is_dir():
        for path in sorted(licenses.glob("*.txt")):
            lines.extend(["", path.name, path.read_text(encoding="utf-8", errors="replace")])

    (output / "THIRD-PARTY.txt").write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")

    with zipfile.ZipFile(output / "MPL-SOURCES.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        for source in sorted(mpl_sources, key=lambda path: path.name):
            archive.write(source, source.name)

    sbom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "asl-infra",
                "version": args.version,
                "licenses": [
                    {"expression": application.get("license") or "MIT"}
                ],
            }
        },
        "components": components,
    }
    (output / "sbom.cdx.json").write_text(
        json.dumps(sbom, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
