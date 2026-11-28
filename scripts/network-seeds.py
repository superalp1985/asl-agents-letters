#!/usr/bin/env python3
"""Sign or verify the V1 network-seeds envelope consumed by ASL."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

MAX_FILE_BYTES = 16_384
MAX_NODES = 32
MAX_ADDRESSES_PER_NODE = 8
MAX_STRING_BYTES = 512
ROLE_NAMES = {"bootstrap", "relay", "autonat"}
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def fail(message: str) -> None:
    raise ValueError(message)


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def read_json(path: Path) -> object:
    data = path.read_bytes()
    if len(data) > MAX_FILE_BYTES:
        fail(f"input exceeds {MAX_FILE_BYTES} bytes")
    return json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)


def require_object(value: object, fields: set[str], name: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        fail(f"{name} must contain exactly: {', '.join(sorted(fields))}")
    return value


def require_string(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        fail(f"{name} must be a non-empty string of at most {maximum} UTF-8 bytes")
    if any(ord(char) < 0x20 for char in value):
        fail(f"{name} contains a control character")
    return value


def require_integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > 2**64 - 1:
        fail(f"{name} must be an unsigned 64-bit integer")
    return value


def base58_decode(value: str) -> bytes:
    number = 0
    for character in value:
        digit = BASE58_ALPHABET.find(character)
        if digit < 0:
            fail("peer_id is not canonical base58")
        number = number * 58 + digit
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    decoded = b"\0" * (len(value) - len(value.lstrip("1"))) + body
    if len(decoded) < 2 or len(decoded) > 128:
        fail("peer_id decoded length is invalid")
    return decoded


def validate_payload(value: object, now_ms: int) -> dict[str, object]:
    payload = require_object(
        value,
        {"version", "network_id", "generated_at_ms", "expires_at_ms", "nodes"},
        "payload",
    )
    if isinstance(payload["version"], bool) or not isinstance(payload["version"], int) or payload["version"] != 1:
        fail("payload.version must be 1")
    network_id = require_string(payload["network_id"], "network_id", 128)
    generated = require_integer(payload["generated_at_ms"], "generated_at_ms")
    expires = require_integer(payload["expires_at_ms"], "expires_at_ms")
    if generated > now_ms or expires <= now_ms or expires <= generated:
        fail("seed timestamps must be current and expires_at_ms must follow generated_at_ms")

    nodes = payload["nodes"]
    if not isinstance(nodes, list) or not 2 <= len(nodes) <= MAX_NODES:
        fail(f"nodes must contain 2 to {MAX_NODES} entries")

    operators: set[str] = set()
    peers: set[str] = set()
    all_addresses: set[str] = set()
    for index, raw_node in enumerate(nodes):
        node = require_object(
            raw_node,
            {"operator_id", "peer_id", "multiaddrs", "roles"},
            f"nodes[{index}]",
        )
        operator = require_string(node["operator_id"], f"nodes[{index}].operator_id", 128)
        peer = require_string(node["peer_id"], f"nodes[{index}].peer_id", 128)
        base58_decode(peer)
        if operator in operators or peer in peers:
            fail("each seed node must have a distinct operator_id and peer_id")
        operators.add(operator)
        peers.add(peer)

        addresses = node["multiaddrs"]
        if not isinstance(addresses, list) or not 1 <= len(addresses) <= MAX_ADDRESSES_PER_NODE:
            fail(f"nodes[{index}].multiaddrs must contain 1 to {MAX_ADDRESSES_PER_NODE} entries")
        seen_addresses: set[str] = set()
        for address in addresses:
            address = require_string(address, f"nodes[{index}].multiaddrs[]", MAX_STRING_BYTES)
            if not address.startswith("/") or not address.endswith(f"/p2p/{peer}"):
                fail(f"nodes[{index}] multiaddrs must end in their matching /p2p/<peer_id>")
            if address in seen_addresses or address in all_addresses:
                fail("seed set contains a duplicate multiaddr")
            seen_addresses.add(address)
            all_addresses.add(address)
            if len(all_addresses) > 32:
                fail("seed set exceeds the runtime's 32 bootstrap address limit")

        roles = node["roles"]
        if (
            not isinstance(roles, list)
            or not roles
            or any(not isinstance(role, str) or role not in ROLE_NAMES for role in roles)
            or len(set(roles)) != len(roles)
            or "bootstrap" not in roles
        ):
            fail(f"nodes[{index}].roles must be unique V1 roles and include bootstrap")

    if len(operators) < 2:
        fail("production seed sets require at least two independent operator_id values")

    # Rebuild dictionaries in the serde struct field order used by the runtime.
    return {
        "version": 1,
        "network_id": network_id,
        "generated_at_ms": generated,
        "expires_at_ms": expires,
        "nodes": [
            {
                "operator_id": node["operator_id"],
                "peer_id": node["peer_id"],
                "multiaddrs": node["multiaddrs"],
                "roles": node["roles"],
            }
            for node in nodes
        ],
    }


def compact_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def openssl_path() -> str:
    executable = shutil.which("openssl")
    if not executable:
        fail("OpenSSL 3 is required")
    result = subprocess.run(
        [executable, "version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode or not re.match(r"OpenSSL 3(?:\.| )", result.stdout):
        fail("OpenSSL 3 is required")
    return executable


def run_openssl(arguments: list[str]) -> None:
    result = subprocess.run(
        [openssl_path(), *arguments],
        stdin=None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        fail(f"OpenSSL operation failed{': ' + detail if detail else ''}")


def raw_public_key(private_key: Path, temporary: Path) -> bytes:
    der_path = temporary / "public.der"
    run_openssl(
        [
            "pkey",
            "-in",
            str(private_key),
            "-pubout",
            "-outform",
            "DER",
            "-out",
            str(der_path),
        ]
    )
    der = der_path.read_bytes()
    if len(der) != 44 or not der.startswith(ED25519_SPKI_PREFIX):
        fail("release key must be an Ed25519 private key")
    return der[-32:]


def public_pem(raw_key: bytes) -> bytes:
    encoded = base64.b64encode(ED25519_SPKI_PREFIX + raw_key).decode("ascii")
    lines = "\n".join(encoded[index : index + 64] for index in range(0, len(encoded), 64))
    return f"-----BEGIN PUBLIC KEY-----\n{lines}\n-----END PUBLIC KEY-----\n".encode("ascii")


def is_inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def sign(args: argparse.Namespace) -> None:
    repo = Path(__file__).resolve().parent.parent
    private_key = args.private_key.resolve(strict=True)
    output = args.output.resolve()
    public_output = args.public_key_output.resolve()
    for path in (private_key, output, public_output):
        if is_inside(path, repo):
            fail("private keys and production seed outputs must stay outside the repository")
    if output == public_output or output.exists() or public_output.exists():
        fail("choose two new, distinct output paths; existing files are never overwritten")
    if not args.private_key.is_file():
        fail("private key must be a regular file")
    if os.name != "nt" and private_key.stat().st_mode & 0o077:
        fail("private key permissions must deny group and other access")
    if not args.payload.is_file():
        fail("payload must be an existing regular file")

    now_ms = time.time_ns() // 1_000_000
    payload = validate_payload(read_json(args.payload), now_ms)
    payload_bytes = compact_json(payload)
    signature_path_parent = output.parent
    if not signature_path_parent.is_dir() or not public_output.parent.is_dir():
        fail("output parent directories must already exist")

    with tempfile.TemporaryDirectory(prefix=".asl-seeds-", dir=signature_path_parent) as directory:
        temporary = Path(directory)
        message_path = temporary / "payload.json"
        signature_path = temporary / "signature.bin"
        message_path.write_bytes(payload_bytes)
        run_openssl(
            [
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(private_key),
                "-in",
                str(message_path),
                "-out",
                str(signature_path),
            ]
        )
        raw_key = raw_public_key(private_key, temporary)
        key_path = temporary / "public.pem"
        key_path.write_bytes(public_pem(raw_key))
        run_openssl(
            [
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(key_path),
                "-rawin",
                "-in",
                str(message_path),
                "-sigfile",
                str(signature_path),
            ]
        )
        envelope = {"payload": payload, "signature": signature_path.read_bytes().hex()}
        encoded = compact_json(envelope) + b"\n"
        if len(encoded) > MAX_FILE_BYTES:
            fail(f"signed seed file exceeds {MAX_FILE_BYTES} bytes")

    created_output = False
    created_public_output = False
    try:
        with output.open("xb") as output_file:
            created_output = True
            output_file.write(encoded)
        with public_output.open("x", encoding="ascii", newline="\n") as key_file:
            created_public_output = True
            key_file.write(raw_key.hex() + "\n")
    except OSError:
        if created_output:
            output.unlink(missing_ok=True)
        if created_public_output:
            public_output.unlink(missing_ok=True)
        raise
    print(f"Signed seeds: {output}")
    print(f"Public key: {public_output}")
    print(f"Public-key SHA-256: {hashlib.sha256(raw_key).hexdigest()}")


def verify(args: argparse.Namespace) -> None:
    now_ms = time.time_ns() // 1_000_000
    envelope = require_object(read_json(args.seeds), {"payload", "signature"}, "envelope")
    payload = validate_payload(envelope["payload"], now_ms)
    signature_hex = envelope["signature"]
    if not isinstance(signature_hex, str) or not re.fullmatch(r"[0-9a-fA-F]{128}", signature_hex):
        fail("signature must be exactly 64 bytes encoded as hexadecimal")

    key_text = args.public_key_file.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"(?:0x)?[0-9a-fA-F]{64}", key_text):
        fail("public key file must contain one raw 32-byte Ed25519 key as hexadecimal")
    raw_key = bytes.fromhex(key_text.removeprefix("0x"))
    if args.network_id is not None and payload["network_id"] != args.network_id:
        fail("seed payload does not match the expected network_id")

    with tempfile.TemporaryDirectory(prefix=".asl-seeds-", dir=args.seeds.resolve().parent) as directory:
        temporary = Path(directory)
        key_path = temporary / "public.pem"
        message_path = temporary / "payload.json"
        signature_path = temporary / "signature.bin"
        key_path.write_bytes(public_pem(raw_key))
        message_path.write_bytes(compact_json(payload))
        signature_path.write_bytes(bytes.fromhex(signature_hex))
        run_openssl(
            [
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(key_path),
                "-rawin",
                "-in",
                str(message_path),
                "-sigfile",
                str(signature_path),
            ]
        )
    print(f"Verified network_id: {payload['network_id']}")
    print(f"Public-key SHA-256: {hashlib.sha256(raw_key).hexdigest()}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    sign_parser = commands.add_parser("sign", help="sign a supplied V1 payload with an external Ed25519 key")
    sign_parser.add_argument("--payload", required=True, type=Path)
    sign_parser.add_argument("--private-key", required=True, type=Path)
    sign_parser.add_argument("--output", required=True, type=Path)
    sign_parser.add_argument("--public-key-output", required=True, type=Path)
    sign_parser.set_defaults(run=sign)

    verify_parser = commands.add_parser("verify", help="verify a V1 seed envelope offline")
    verify_parser.add_argument("--seeds", required=True, type=Path)
    verify_parser.add_argument("--public-key-file", required=True, type=Path)
    verify_parser.add_argument("--network-id")
    verify_parser.set_defaults(run=verify)
    return parser.parse_args()


def main() -> int:
    try:
        args = parse_args()
        args.run(args)
        return 0
    except (OSError, UnicodeError, json.JSONDecodeError, subprocess.SubprocessError, ValueError) as error:
        print(f"network-seeds: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
