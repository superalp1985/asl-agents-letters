#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
import zipfile

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from release_tools.manifest import (  # noqa: E402
    MAX_MANIFEST_BYTES,
    ReleaseError,
    load_public_key,
    verify_manifest,
)
from release_tools.release_key import PUBLIC_KEY  # noqa: E402

DEFAULT_TAG = "v1.0.0-rc.2"
REPOSITORY_RELEASE_URL = (
    "https://github.com/superalp1985/asl-agents-letters/releases/download"
)
MANIFEST_NAME = "asl-release-manifest.json"
SIGNATURE_NAME = MANIFEST_NAME + ".sig"
MAX_ASSET_BYTES = 2 * 1024 * 1024 * 1024
MAX_EXTRACTED_BYTES = 4 * 1024 * 1024 * 1024
MAX_EXTRACTED_MEMBERS = 512


class BootstrapError(RuntimeError):
    pass


def target_platform() -> tuple[str, str]:
    if sys.platform == "win32":
        os_name = "windows"
    elif sys.platform.startswith("linux"):
        os_name = "linux"
    else:
        raise BootstrapError(f"unsupported operating system: {sys.platform}")
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        arch = "x86_64"
    elif machine in {"aarch64", "arm64"}:
        arch = "aarch64"
    else:
        raise BootstrapError(f"unsupported CPU architecture: {machine}")
    return os_name, arch


def default_install_root(os_name: str) -> Path:
    if os_name == "windows":
        base = os.environ.get("LOCALAPPDATA")
        if not base:
            raise BootstrapError("LOCALAPPDATA is not set")
        return Path(base) / "ASL" / "client"
    return Path.home() / ".local"


def default_data_home(os_name: str) -> Path:
    if os_name == "windows":
        base = os.environ.get("LOCALAPPDATA")
        if not base:
            raise BootstrapError("LOCALAPPDATA is not set")
        return Path(base) / "ASL" / "data"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "asl"


def download(url: str, destination: Path, *, maximum: int) -> None:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/octet-stream",
            "User-Agent": "ASL-Bootstrap/1",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            length = response.headers.get("Content-Length")
            if length and int(length) > maximum:
                raise BootstrapError(f"download exceeds size limit: {url}")
            total = 0
            with destination.open("xb") as output:
                while block := response.read(1024 * 1024):
                    total += len(block)
                    if total > maximum:
                        raise BootstrapError(f"download exceeds size limit: {url}")
                    output.write(block)
    except Exception:
        destination.unlink(missing_ok=True)
        raise


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def verify_asset(path: Path, asset: dict) -> None:
    size = path.stat().st_size
    if size != asset["size"]:
        raise BootstrapError(f"asset size mismatch: {asset['name']}")
    if sha256_file(path) != asset["sha256"]:
        raise BootstrapError(f"asset SHA-256 mismatch: {asset['name']}")


def safe_parts(name: str) -> tuple[str, ...]:
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise BootstrapError(f"unsafe archive path: {name}")
    return path.parts


def extract_zip(archive: Path, destination: Path) -> None:
    total = 0
    with zipfile.ZipFile(archive) as source:
        members = source.infolist()
        if not 1 <= len(members) <= MAX_EXTRACTED_MEMBERS:
            raise BootstrapError("ZIP member count is outside the supported range")
        for member in members:
            parts = safe_parts(member.filename)
            mode = (member.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise BootstrapError(f"ZIP symlink refused: {member.filename}")
            target = destination.joinpath(*parts)
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if member.flag_bits & 0x1:
                raise BootstrapError("encrypted ZIP members are not supported")
            total += member.file_size
            if total > MAX_EXTRACTED_BYTES:
                raise BootstrapError("ZIP expands beyond the size limit")
            target.parent.mkdir(parents=True, exist_ok=True)
            with source.open(member) as input_stream, target.open("xb") as output:
                shutil.copyfileobj(input_stream, output, length=1024 * 1024)


def extract_tar(archive: Path, destination: Path) -> None:
    total = 0
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        if not 1 <= len(members) <= MAX_EXTRACTED_MEMBERS:
            raise BootstrapError("tar member count is outside the supported range")
        for member in members:
            parts = safe_parts(member.name)
            if member.issym() or member.islnk() or member.ischr() or member.isblk() or member.isfifo():
                raise BootstrapError(f"special tar member refused: {member.name}")
            target = destination.joinpath(*parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise BootstrapError(f"unsupported tar member: {member.name}")
            total += member.size
            if total > MAX_EXTRACTED_BYTES:
                raise BootstrapError("tar expands beyond the size limit")
            target.parent.mkdir(parents=True, exist_ok=True)
            stream = source.extractfile(member)
            if stream is None:
                raise BootstrapError(f"cannot read tar member: {member.name}")
            with stream, target.open("xb") as output:
                shutil.copyfileobj(stream, output, length=1024 * 1024)
            target.chmod(member.mode & 0o777)


def choose_asset(document: dict, os_name: str, arch: str, kind: str) -> dict:
    matches = [
        asset
        for asset in document["assets"]
        if asset["os"] == os_name and asset["arch"] == arch and asset["kind"] == kind
    ]
    if len(matches) != 1:
        raise BootstrapError(
            f"expected exactly one {kind} asset for {os_name}/{arch}, found {len(matches)}"
        )
    return matches[0]


def find_asset(document: dict, os_name: str, arch: str) -> dict:
    if os_name == "windows":
        return choose_asset(document, os_name, arch, "client")
    return choose_asset(document, os_name, arch, "client")


def self_check(document: dict, os_name: str, arch: str) -> None:
    if not getattr(sys, "frozen", False):
        return
    matches = [
        asset
        for asset in document["assets"]
        if asset["os"] == os_name and asset["arch"] == arch and asset["kind"] == "bootstrap"
    ]
    if len(matches) != 1:
        raise BootstrapError("release manifest does not identify this bootstrap")
    actual = sha256_file(Path(sys.executable).resolve())
    if actual != matches[0]["sha256"]:
        raise BootstrapError("running bootstrap does not match the signed release")


def run_command(command: list[str], *, cwd: Path | None = None) -> None:
    print("+ " + " ".join(command))
    subprocess.run(command, cwd=cwd, check=True)


def install_windows(
    package: Path,
    document: dict,
    *,
    install_root: Path,
    data_home: Path,
    launch: bool,
) -> Path:
    install_root.mkdir(parents=True, exist_ok=True)
    release = install_root / f"{document['version']}-{choose_asset(document, 'windows', target_platform()[1], 'client')['sha256'][:12]}"
    if not release.exists():
        staging = Path(tempfile.mkdtemp(prefix=".asl-install-", dir=install_root))
        try:
            extract_zip(package, staging)
            for required in ("asl.exe", "asl-core.exe", "asl-ui.exe", "Start-ASL.ps1", "vcruntime140.dll"):
                if not (staging / required).is_file():
                    raise BootstrapError(f"Windows package is missing {required}")
            os.replace(staging, release)
        finally:
            if staging.exists():
                shutil.rmtree(staging, ignore_errors=True)
    data_home.mkdir(parents=True, exist_ok=True)
    if launch:
        shell = shutil.which("pwsh.exe") or shutil.which("powershell.exe")
        if not shell:
            raise BootstrapError("PowerShell is required to launch the Windows client")
        run_command(
            [
                shell,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(release / "Start-ASL.ps1"),
                "-DataDirectory",
                str(data_home),
            ],
            cwd=release,
        )
    return release


def install_linux(
    package: Path,
    document: dict,
    *,
    install_root: Path,
    data_home: Path,
    launch: bool,
    system_dependencies: bool,
) -> Path:
    with tempfile.TemporaryDirectory(prefix="asl-bootstrap-") as raw:
        extracted = Path(raw)
        extract_tar(package, extracted)
        roots = [entry for entry in extracted.iterdir() if entry.is_dir()]
        if len(roots) != 1 or not (roots[0] / "install.sh").is_file():
            raise BootstrapError("Linux package root or install.sh is missing")
        package_root = roots[0]
        command = [
            "bash",
            str(package_root / "install.sh"),
            "--prefix",
            str(install_root),
            "--asl-home",
            str(data_home),
        ]
        if system_dependencies:
            command.append("--install-system-dependencies")
        run_command(command, cwd=package_root)
    if launch:
        run_command([str(install_root / "bin" / "asl-launch")])
    return install_root


def load_release(
    args: argparse.Namespace,
    temporary: Path,
    public_key,
) -> dict:
    manifest_path = args.manifest_file
    signature_path = args.signature_file
    if manifest_path is None and args.asset_dir:
        manifest_path = args.asset_dir / MANIFEST_NAME
        signature_path = args.asset_dir / SIGNATURE_NAME
    if manifest_path:
        if signature_path is None:
            raise BootstrapError("--signature-file is required with --manifest-file")
        manifest = manifest_path.read_bytes()
        signature = signature_path.read_bytes()
    else:
        release_url = args.release_url or f"{REPOSITORY_RELEASE_URL}/{args.tag}"
        manifest = temporary / MANIFEST_NAME
        signature = temporary / SIGNATURE_NAME
        download(release_url.rstrip("/") + "/" + MANIFEST_NAME, manifest, maximum=MAX_MANIFEST_BYTES)
        download(release_url.rstrip("/") + "/" + SIGNATURE_NAME, signature, maximum=1024)
        manifest = manifest.read_bytes()
        signature = signature.read_bytes()
    document = verify_manifest(public_key, manifest, signature)
    if args.tag and document["tag"] != args.tag:
        raise BootstrapError("signed manifest tag does not match the requested release")
    self_check(document, *target_platform())
    return document


def obtain_asset(
    args: argparse.Namespace,
    temporary: Path,
    document: dict,
    asset: dict,
) -> Path:
    if args.asset_dir:
        path = args.asset_dir / asset["name"]
    else:
        release_url = args.release_url or f"{REPOSITORY_RELEASE_URL}/{document['tag']}"
        path = temporary / asset["name"]
        download(
            release_url.rstrip("/") + "/" + urllib.parse.quote(asset["name"], safe=""),
            path,
            maximum=MAX_ASSET_BYTES,
        )
    if not path.is_file() or path.is_symlink():
        raise BootstrapError(f"asset is missing or unsafe: {path}")
    verify_asset(path, asset)
    return path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify, download, install and launch an ASL desktop client",
    )
    parser.add_argument("--tag", default=DEFAULT_TAG)
    parser.add_argument("--release-url")
    parser.add_argument("--asset-dir", type=Path)
    parser.add_argument("--manifest-file", type=Path)
    parser.add_argument("--signature-file", type=Path)
    parser.add_argument("--install-root", type=Path)
    parser.add_argument("--asl-home", type=Path)
    parser.add_argument("--no-launch", action="store_true")
    parser.add_argument("--skip-system-dependencies", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    public_key = load_public_key(PUBLIC_KEY)
    os_name, arch = target_platform()
    install_root = (args.install_root or default_install_root(os_name)).resolve()
    data_home = (args.asl_home or default_data_home(os_name)).resolve()
    with tempfile.TemporaryDirectory(prefix="asl-release-") as raw:
        temporary = Path(raw)
        document = load_release(args, temporary, public_key)
        asset = find_asset(document, os_name, arch)
        if args.dry_run:
            print(f"Release: {document['tag']} {document['version']}")
            print(f"Platform: {os_name}/{arch}")
            print(f"Asset: {asset['name']} ({asset['size']} bytes)")
            print(f"Install root: {install_root}")
            print(f"ASL home: {data_home}")
            return 0
        package = obtain_asset(args, temporary, document, asset)
        if os_name == "windows":
            release = install_windows(
                package,
                document,
                install_root=install_root,
                data_home=data_home,
                launch=not args.no_launch,
            )
        else:
            release = install_linux(
                package,
                document,
                install_root=install_root,
                data_home=data_home,
                launch=not args.no_launch,
                system_dependencies=not args.skip_system_dependencies,
            )
        print(f"Installed ASL release at {release}")
        print(f"ASL_HOME={data_home}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (BootstrapError, ReleaseError, OSError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
