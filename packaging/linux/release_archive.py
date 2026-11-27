#!/usr/bin/env python3
"""Inspect and safely extract an ASL Linux infrastructure release archive."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile

MAX_MEMBERS = 128
MAX_UNPACKED_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
VERSION_PATTERN = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
REQUIRED_FILES = {
    "asl-infra",
    "asl-infra.service.in",
    "infra.example.toml",
    "install.sh",
    "upgrade.sh",
    "rollback.sh",
    "release-common.sh",
    "verify-release.sh",
    "verify-offline-release.sh",
    "release_archive.py",
    "README.md",
    "LICENSE",
    "THIRD-PARTY.txt",
    "sbom.cdx.json",
    "MPL-SOURCES.zip",
    "BUILD-INFO.json",
    "SHA256SUMS",
}


class ArchiveError(ValueError):
    pass


def inspect_archive(path: Path) -> tuple[tarfile.TarFile, str, dict[str, tarfile.TarInfo]]:
    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ArchiveError("archive exceeds the supported size limit")
    archive = tarfile.open(path, mode="r:gz")
    try:
        members = archive.getmembers()
        if not members or len(members) > MAX_MEMBERS:
            raise ArchiveError("archive member count is outside the supported range")

        root: str | None = None
        files: dict[str, tarfile.TarInfo] = {}
        total_bytes = 0
        seen: set[str] = set()
        for member in members:
            raw_name = member.name
            raw_parts = raw_name.split("/")
            if raw_parts and raw_parts[-1] == "":
                raw_parts.pop()
            if (
                "\\" in raw_name
                or raw_name.startswith("/")
                or not raw_parts
                or any(part in ("", ".", "..") for part in raw_parts)
            ):
                raise ArchiveError(f"unsafe archive path: {raw_name!r}")
            name = PurePosixPath(raw_name)
            if root is None:
                root = name.parts[0]
                if not root.startswith("asl-infra-linux-"):
                    raise ArchiveError("archive must have one asl-infra-linux-* root directory")
            if name.parts[0] != root or len(name.parts) > 2:
                raise ArchiveError("archive entries must be direct children of one package directory")
            normalized = name.as_posix().rstrip("/")
            if normalized in seen:
                raise ArchiveError(f"duplicate archive path: {normalized}")
            seen.add(normalized)
            if len(name.parts) == 1:
                if not member.isdir():
                    raise ArchiveError("archive root must be a directory")
                continue
            if not member.isfile():
                raise ArchiveError(f"non-regular archive member refused: {normalized}")
            total_bytes += member.size
            if member.size < 0 or total_bytes > MAX_UNPACKED_BYTES:
                raise ArchiveError("archive expands beyond the supported size limit")
            files[name.parts[1]] = member

        if root is None or set(files) != REQUIRED_FILES:
            missing = sorted(REQUIRED_FILES - set(files))
            unexpected = sorted(set(files) - REQUIRED_FILES)
            raise ArchiveError(f"package file set mismatch; missing={missing}, unexpected={unexpected}")
        verify_inner_checksums(archive, files)
        verify_metadata(archive, root, files)
        return archive, root, files
    except Exception:
        archive.close()
        raise


def digest_member(archive: tarfile.TarFile, member: tarfile.TarInfo) -> str:
    stream = archive.extractfile(member)
    if stream is None:
        raise ArchiveError(f"cannot read archive member: {member.name}")
    digest = hashlib.sha256()
    with stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_inner_checksums(
    archive: tarfile.TarFile, files: dict[str, tarfile.TarInfo]
) -> None:
    manifest = archive.extractfile(files["SHA256SUMS"])
    if manifest is None:
        raise ArchiveError("package SHA256SUMS cannot be read")
    try:
        with manifest:
            lines = manifest.read(64 * 1024 + 1).decode("ascii").splitlines()
    except UnicodeError as error:
        raise ArchiveError("package SHA256SUMS is not ASCII") from error
    if len(lines) > len(files) or not lines:
        raise ArchiveError("package SHA256SUMS has an invalid line count")
    entries: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  \./([A-Za-z0-9_.-]+)", line)
        if not match:
            raise ArchiveError("package SHA256SUMS contains an invalid entry")
        digest, filename = match.groups()
        if filename == "SHA256SUMS" or filename in entries or filename not in files:
            raise ArchiveError("package SHA256SUMS contains a duplicate or unknown file")
        entries[filename] = digest
    expected = set(files) - {"SHA256SUMS"}
    if set(entries) != expected:
        raise ArchiveError("package SHA256SUMS does not cover every package file")
    if list(entries) != sorted(expected):
        raise ArchiveError("package SHA256SUMS entries are not in canonical path order")
    for filename, expected_digest in entries.items():
        if digest_member(archive, files[filename]) != expected_digest:
            raise ArchiveError(f"package checksum mismatch: {filename}")


def read_member(archive: tarfile.TarFile, member: tarfile.TarInfo, limit: int) -> bytes:
    if member.size > limit:
        raise ArchiveError(f"metadata file exceeds its size limit: {member.name}")
    stream = archive.extractfile(member)
    if stream is None:
        raise ArchiveError(f"cannot read metadata file: {member.name}")
    with stream:
        return stream.read(limit + 1)


def verify_metadata(
    archive: tarfile.TarFile,
    root: str,
    files: dict[str, tarfile.TarInfo],
) -> None:
    try:
        build = json.loads(read_member(archive, files["BUILD-INFO.json"], 16_384))
        sbom = json.loads(read_member(archive, files["sbom.cdx.json"], 8 * 1024 * 1024))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ArchiveError("release metadata is not valid UTF-8 JSON") from error
    if (
        not isinstance(build, dict)
        or build.get("format_version") != 1
        or build.get("product") != "asl-infra"
        or not isinstance(build.get("version"), str)
        or not VERSION_PATTERN.fullmatch(build["version"])
        or root != f"asl-infra-linux-{build.get('architecture')}-{build.get('version')}"
        or build.get("architecture") not in {"x86_64", "aarch64"}
        or not isinstance(build.get("git_commit"), str)
        or not re.fullmatch(r"[0-9a-f]{40}", build["git_commit"])
        or not isinstance(build.get("target"), str)
        or not re.fullmatch(r"(?:x86_64|aarch64)-[A-Za-z0-9_.+-]+-linux-[A-Za-z0-9_.+-]+", build["target"])
        or not build["target"].startswith(f"{build.get('architecture')}-")
        or isinstance(build.get("source_date_epoch"), bool)
        or not isinstance(build.get("source_date_epoch"), int)
        or not 315532800 <= build["source_date_epoch"] <= 4354819198
        or not isinstance(sbom, dict)
        or sbom.get("bomFormat") != "CycloneDX"
        or sbom.get("specVersion") != "1.6"
        or sbom.get("metadata", {}).get("component", {}).get("name") != "asl-infra"
        or sbom.get("metadata", {}).get("component", {}).get("version") != build.get("version")
    ):
        raise ArchiveError("release metadata does not match the supported package contract")
    expected_source_date = datetime.fromtimestamp(
        build["source_date_epoch"], timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    if build.get("source_date") != expected_source_date:
        raise ArchiveError("release source date does not match source_date_epoch")


def extract_archive(path: Path, destination: Path) -> Path:
    archive, root, files = inspect_archive(path)
    try:
        root_path = destination / root
        root_path.mkdir(mode=0o755)
        for filename, member in files.items():
            output = root_path / filename
            stream = archive.extractfile(member)
            if stream is None:
                raise ArchiveError(f"cannot read archive member: {member.name}")
            mode = 0o755 if member.mode & 0o111 else 0o644
            with stream, output.open("xb") as target:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    target.write(block)
            output.chmod(mode)
        return root_path
    finally:
        archive.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("archive", type=Path)
    extract = commands.add_parser("extract")
    extract.add_argument("archive", type=Path)
    extract.add_argument("destination", type=Path)
    compare = commands.add_parser("require-upgrade")
    compare.add_argument("new_version")
    compare.add_argument("current_version")
    args = parser.parse_args()
    try:
        if args.command == "require-upgrade":
            if not VERSION_PATTERN.fullmatch(args.new_version) or not VERSION_PATTERN.fullmatch(
                args.current_version
            ):
                raise ArchiveError("release versions must be stable X.Y.Z SemVer values")
            new_version = tuple(int(part) for part in args.new_version.split("."))
            current_version = tuple(int(part) for part in args.current_version.split("."))
            if new_version <= current_version:
                raise ArchiveError(
                    f"upgrade {args.new_version} must be strictly newer than {args.current_version}"
                )
            print(f"Upgrade version accepted: {args.current_version} -> {args.new_version}")
        elif args.command == "verify":
            archive, root, _ = inspect_archive(args.archive)
            archive.close()
            print(f"Verified package contents: {root}")
        else:
            extracted = extract_archive(args.archive, args.destination)
            print(extracted)
        return 0
    except (OSError, tarfile.TarError, ArchiveError, json.JSONDecodeError) as error:
        print(f"release archive: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
