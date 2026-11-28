from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

FORMAT_VERSION = 1
PRODUCT = "asl"
ALGORITHM = "RSA-4096-SHA256-PKCS1v15"
DOMAIN = b"ASL-RELEASE-MANIFEST-v1\0"
MAX_MANIFEST_BYTES = 1024 * 1024
ASSET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,254}")
SAFE_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?")
TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?")
SHA256 = re.compile(r"[0-9a-f]{64}")


class ReleaseError(RuntimeError):
    pass


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ReleaseError("invalid base64url value")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ReleaseError("invalid base64url alphabet")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def canonical_json(document: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            document,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


def public_key_document(public_key: rsa.RSAPublicKey) -> dict[str, Any]:
    numbers = public_key.public_numbers()
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "algorithm": ALGORITHM,
        "exponent": _b64url_encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
        "fingerprint_sha256": hashlib.sha256(der).hexdigest(),
        "format_version": FORMAT_VERSION,
        "key_id": "sha256:" + hashlib.sha256(der).hexdigest(),
        "modulus": _b64url_encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
    }


def load_public_key(document: dict[str, Any]) -> rsa.RSAPublicKey:
    if document.get("format_version") != FORMAT_VERSION:
        raise ReleaseError("unsupported public-key format")
    if document.get("algorithm") != ALGORITHM:
        raise ReleaseError("unsupported public-key algorithm")
    modulus = int.from_bytes(_b64url_decode(document.get("modulus")), "big")
    exponent = int.from_bytes(_b64url_decode(document.get("exponent")), "big")
    if modulus.bit_length() < 3072 or exponent < 65537:
        raise ReleaseError("release public key is too weak")
    key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
    actual = public_key_document(key)
    if actual["fingerprint_sha256"] != document.get("fingerprint_sha256"):
        raise ReleaseError("public-key fingerprint mismatch")
    return key


def generate_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


def private_key_pem(private_key: rsa.RSAPrivateKey) -> bytes:
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def load_private_key(path: Path) -> rsa.RSAPrivateKey:
    data = path.read_bytes()
    if len(data) > 64 * 1024:
        raise ReleaseError("private key file is oversized")
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 3072:
        raise ReleaseError("private key must be RSA with at least 3072 bits")
    return key


def sign_manifest(private_key: rsa.RSAPrivateKey, manifest_bytes: bytes) -> bytes:
    if not manifest_bytes or len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise ReleaseError("manifest size is invalid")
    return private_key.sign(
        DOMAIN + manifest_bytes,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def verify_manifest(
    public_key: rsa.RSAPublicKey,
    manifest_bytes: bytes,
    signature: bytes,
) -> dict[str, Any]:
    if not manifest_bytes or len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise ReleaseError("manifest size is invalid")
    expected_signature_size = (public_key.key_size + 7) // 8
    if len(signature) != expected_signature_size:
        raise ReleaseError("manifest signature size is invalid")
    try:
        public_key.verify(
            signature,
            DOMAIN + manifest_bytes,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except Exception as error:
        raise ReleaseError("manifest signature verification failed") from error
    try:
        document = json.loads(manifest_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseError("signed manifest is not valid UTF-8 JSON") from error
    validate_manifest(document)
    if canonical_json(document) != manifest_bytes:
        raise ReleaseError("signed manifest is not canonical JSON")
    return document


def _require_string(value: Any, label: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value:
        raise ReleaseError(f"{label} must be a non-empty string")
    if pattern is not None and not pattern.fullmatch(value):
        raise ReleaseError(f"{label} has invalid characters or length")
    return value


def validate_manifest(document: Any) -> None:
    if not isinstance(document, dict):
        raise ReleaseError("manifest root must be an object")
    if document.get("format_version") != FORMAT_VERSION:
        raise ReleaseError("unsupported release-manifest format")
    if document.get("product") != PRODUCT:
        raise ReleaseError("release manifest product mismatch")
    _require_string(document.get("version"), "version", VERSION)
    _require_string(document.get("tag"), "tag", TAG)
    _require_string(document.get("commit"), "commit", re.compile(r"[0-9a-f]{40}"))
    _require_string(
        document.get("generated_at"),
        "generated_at",
        re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"),
    )
    assets = document.get("assets")
    if not isinstance(assets, list) or not 1 <= len(assets) <= 64:
        raise ReleaseError("release manifest assets are invalid")
    seen: set[tuple[str, str, str, str, str]] = set()
    for asset in assets:
        if not isinstance(asset, dict):
            raise ReleaseError("release asset must be an object")
        os_name = _require_string(asset.get("os"), "asset os", SAFE_TOKEN)
        arch = _require_string(asset.get("arch"), "asset arch", SAFE_TOKEN)
        distribution = _require_string(
            asset.get("distribution"),
            "asset distribution",
            SAFE_TOKEN,
        )
        kind = _require_string(asset.get("kind"), "asset kind", SAFE_TOKEN)
        name = _require_string(asset.get("name"), "asset name", ASSET_NAME)
        digest = _require_string(asset.get("sha256"), "asset sha256", SHA256)
        size = asset.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= 2**31:
            raise ReleaseError("asset size is invalid")
        key = (os_name, arch, distribution, kind, name)
        if key in seen:
            raise ReleaseError("release manifest repeats an asset")
        seen.add(key)


def asset_record(
    path: Path,
    *,
    os_name: str,
    arch: str,
    distribution: str,
    kind: str,
) -> dict[str, Any]:
    name = path.name
    if not ASSET_NAME.fullmatch(name):
        raise ReleaseError(f"unsafe asset name: {name}")
    size = path.stat().st_size
    if not 1 <= size <= 2**31:
        raise ReleaseError(f"asset size is invalid: {name}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return {
        "arch": arch,
        "distribution": distribution,
        "kind": kind,
        "name": name,
        "os": os_name,
        "sha256": digest.hexdigest(),
        "size": size,
    }
