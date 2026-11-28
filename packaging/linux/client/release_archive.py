#!/usr/bin/env python3
"""Verify and safely extract an ASL Linux desktop client archive."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile

MAX_MEMBERS = 512
MAX_ARCHIVE_BYTES = 4 * 1024 * 1024 * 1024
MAX_UNPACKED_BYTES = 4 * 1024 * 1024 * 1024
ROOT_PATTERN = re.compile(r"asl-client-linux-(x86_64|aarch64)-(\d+\.\d+\.\d+)")

REQUIRED_FILES = {
    "APT-PACKAGES.txt",
    "APT-DEPENDENCIES.txt",
    "BUILD-INFO.json",
    "LICENSE",
    "MPL-SOURCES.zip",
    "README.md",
    "SHA256SUMS",
    "THIRD-PARTY.txt",
    "client-common.sh",
    "install.sh",
    "install-deps.sh",
    "payload/bin/asl",
    "payload/bin/asl-core",
    "payload/bin/asl-extractor",
    "payload/bin/asl-core-service.in",
    "payload/bin/asl-launch.in",
    "payload/bin/asl-net",
    "payload/bin/asl-ui",
    "payload/bin/asl-worker",
    "payload/config/asl.env.example",
    "payload/share/applications/asl.desktop",
    "payload/share/icons/hicolor/256x256/apps/asl.png",
    "payload/share/icons/hicolor/scalable/apps/asl.svg",
    "payload/systemd/asl-core.service.in",
    "release_archive.py",
    "sbom.cdx.json",
    "uninstall.sh",
    "upgrade.sh",
    "verify.sh",
}
OPTIONAL_DEPENDENCY_FILES = {
    "payload/apt-deps/DEB-SHA256SUMS",
    "payload/apt-deps/TARGET-UBUNTU.txt",
}
OPTIONAL_DEB_PATTERN = re.compile(r"payload/apt-deps/[A-Za-z0-9][A-Za-z0-9.+:~%_-]*\.deb")


class ArchiveError(RuntimeError):
    pass


def candidate_name(name: str) -> str:
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
        raise ArchiveError(f"unsafe archive path: {name}")
    return path.as_posix()


def read_member(archive: tarfile.TarFile, member: tarfile.TarInfo, limit: int) -> bytes:
    if member.size > limit:
        raise ArchiveError(f"archive member exceeds the size limit: {member.name}")
    stream = archive.extractfile(member)
    if stream is None:
        raise ArchiveError(f"cannot read archive member: {member.name}")
    data = stream.read(limit + 1)
    if len(data) > limit:
        raise ArchiveError(f"archive member exceeds the size limit: {member.name}")
    return data


def inspect_archive(archive_path: Path) -> tuple[str, str, str, dict[str, tarfile.TarInfo], tarfile.TarFile]:
    if archive_path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ArchiveError("archive exceeds the supported size limit")
    archive = tarfile.open(archive_path, "r:gz")
    members = archive.getmembers()
    if not 1 <= len(members) <= MAX_MEMBERS:
        raise ArchiveError("archive member count is outside the supported range")

    root = ""
    files: dict[str, tarfile.TarInfo] = {}
    total_bytes = 0
    for member in members:
        normalized = candidate_name(member.name)
        parts = PurePosixPath(normalized).parts
        if not root:
            root = parts[0]
        if parts[0] != root:
            archive.close()
            raise ArchiveError("archive contains more than one root directory")
        if member.isdir():
            continue
        if not member.isfile():
            archive.close()
            raise ArchiveError(f"non-regular archive member refused: {member.name}")
        relative = PurePosixPath(*parts[1:]).as_posix()
        if not relative or relative in files:
            archive.close()
            raise ArchiveError(f"duplicate or invalid archive path: {member.name}")
        files[relative] = member
        total_bytes += member.size
        if total_bytes > MAX_UNPACKED_BYTES:
            archive.close()
            raise ArchiveError("archive expands beyond the supported size limit")

    match = ROOT_PATTERN.fullmatch(root)
    if match is None:
        archive.close()
        raise ArchiveError("archive root must be asl-client-linux-<arch>-<version>")
    missing = sorted(REQUIRED_FILES - files.keys())
    optional = {
        name
        for name in files
        if name in OPTIONAL_DEPENDENCY_FILES or OPTIONAL_DEB_PATTERN.fullmatch(name)
    }
    unexpected = sorted(files.keys() - REQUIRED_FILES - optional)
    dependency_metadata = sorted(
        name for name in files if name.startswith("payload/apt-deps/")
    )
    if dependency_metadata:
        if not OPTIONAL_DEPENDENCY_FILES.issubset(files):
            raise ArchiveError("bundled dependency metadata is incomplete")
        if not any(OPTIONAL_DEB_PATTERN.fullmatch(name) for name in files):
            raise ArchiveError("bundled dependency metadata has no .deb files")
    if missing or unexpected:
        archive.close()
        raise ArchiveError(f"package file set mismatch; missing={missing}, unexpected={unexpected}")
    return root, match.group(1), match.group(2), files, archive


def verify_inner_checksums(
    archive: tarfile.TarFile,
    files: dict[str, tarfile.TarInfo],
) -> None:
    raw = read_member(archive, files["SHA256SUMS"], 1024 * 1024)
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise ArchiveError("SHA256SUMS is not ASCII") from error
    lines = text.splitlines()
    if len(lines) != len(files) - 1:
        raise ArchiveError("SHA256SUMS has an invalid line count")

    entries: dict[str, str] = {}
    for line in lines:
        if len(line) < 67 or line[64:66] != "  ":
            raise ArchiveError("SHA256SUMS contains an invalid entry")
        digest = line[:64]
        filename = line[66:]
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or not filename.startswith("./"):
            raise ArchiveError("SHA256SUMS contains an invalid entry")
        filename = filename[2:]
        if filename == "SHA256SUMS" or filename in entries or filename not in files:
            raise ArchiveError("SHA256SUMS contains a duplicate or unknown file")
        entries[filename] = digest
    expected = set(files) - {"SHA256SUMS"}
    if set(entries) != expected:
        raise ArchiveError("SHA256SUMS does not cover every package file")
    if list(entries) != sorted(entries):
        raise ArchiveError("SHA256SUMS entries are not in canonical path order")
    for filename, expected_digest in entries.items():
        member = files[filename]
        stream = archive.extractfile(member)
        if stream is None:
            raise ArchiveError(f"cannot read package member: {filename}")
        digest = hashlib.sha256()
        while block := stream.read(1024 * 1024):
            digest.update(block)
        if digest.hexdigest() != expected_digest:
            raise ArchiveError(f"package checksum mismatch: {filename}")


def verify_metadata(
    archive: tarfile.TarFile,
    files: dict[str, tarfile.TarInfo],
    arch: str,
    version: str,
) -> None:
    try:
        build = json.loads(read_member(archive, files["BUILD-INFO.json"], 64 * 1024))
        sbom = json.loads(read_member(archive, files["sbom.cdx.json"], 1024 * 1024))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ArchiveError("release metadata is not valid UTF-8 JSON") from error
    if not isinstance(build, dict) or not isinstance(sbom, dict):
        raise ArchiveError("release metadata has an invalid shape")
    source_epoch = build.get("source_date_epoch")
    if (
        isinstance(source_epoch, int)
        and not isinstance(source_epoch, bool)
        and 315532800 <= source_epoch <= 4354819198
    ):
        expected_source_date = datetime.fromtimestamp(source_epoch, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    else:
        expected_source_date = ""
    valid = (
        build.get("format_version") == 1
        and build.get("product") == "asl-client"
        and build.get("version") == version
        and build.get("architecture") == arch
        and isinstance(build.get("target"), str)
        and re.fullmatch(
            rf"(?:x86_64|aarch64)-[A-Za-z0-9_.+-]+-linux-[A-Za-z0-9_.+-]+",
            build["target"],
        )
        and isinstance(build.get("git_commit"), str)
        and re.fullmatch(r"[0-9a-f]{40}", build["git_commit"])
        and isinstance(build.get("source_date_epoch"), int)
        and build["source_date_epoch"] > 0
        and build.get("source_date") == expected_source_date
        and isinstance(build.get("glibc_baseline"), str)
        and re.fullmatch(r"[0-9]+\.[0-9]+", build["glibc_baseline"])
        and sbom.get("bomFormat") == "CycloneDX"
        and sbom.get("specVersion") == "1.6"
        and isinstance(sbom.get("metadata"), dict)
        and isinstance(sbom["metadata"].get("component"), dict)
        and sbom["metadata"]["component"].get("name") == "asl-client"
        and sbom["metadata"]["component"].get("version") == version
    )
    if not valid:
        raise ArchiveError("release metadata does not match the supported package contract")


def verify_archive(archive_path: Path) -> str:
    root, arch, version, files, archive = inspect_archive(archive_path)
    try:
        verify_inner_checksums(archive, files)
        verify_metadata(archive, files, arch, version)
    finally:
        archive.close()
    return root


def extract_archive(archive_path: Path, output: Path) -> Path:
    root, arch, version, files, archive = inspect_archive(archive_path)
    try:
        verify_inner_checksums(archive, files)
        verify_metadata(archive, files, arch, version)
        destination = output / root
        destination.mkdir(parents=True, exist_ok=False)
        for relative, member in sorted(files.items()):
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            stream = archive.extractfile(member)
            if stream is None:
                raise ArchiveError(f"cannot read package member: {relative}")
            data = stream.read()
            target.write_bytes(data)
            target.chmod(0o755 if relative.endswith((".sh", ".py")) or "/bin/" in f"/{relative}" else 0o644)
    finally:
        archive.close()
    return destination


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("archive", type=Path)
    extract = commands.add_parser("extract")
    extract.add_argument("archive", type=Path)
    extract.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "verify":
            root = verify_archive(args.archive)
            print(f"Verified ASL Linux client package: {root}")
        else:
            args.output.mkdir(parents=True, exist_ok=True)
            print(extract_archive(args.archive, args.output))
    except (OSError, tarfile.TarError, ArchiveError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
