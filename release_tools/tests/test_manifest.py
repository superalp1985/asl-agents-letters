from __future__ import annotations

import copy
import unittest

from release_tools.manifest import (
    ReleaseError,
    canonical_json,
    generate_private_key,
    public_key_document,
    sign_manifest,
    validate_manifest,
    verify_manifest,
)


def sample_manifest() -> dict:
    return {
        "assets": [
            {
                "arch": "x86_64",
                "distribution": "windows",
                "kind": "client",
                "name": "asl-windows-test.zip",
                "os": "windows",
                "sha256": "a" * 64,
                "size": 123,
            }
        ],
        "commit": "b" * 40,
        "format_version": 1,
        "generated_at": "2026-11-28T12:45:00Z",
        "product": "asl",
        "tag": "v1.0.0-rc.2",
        "version": "1.0.0",
    }


class ManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.private_key = generate_private_key()
        cls.public_key = cls.private_key.public_key()

    def test_round_trip_and_tamper_rejection(self) -> None:
        manifest = canonical_json(sample_manifest())
        signature = sign_manifest(self.private_key, manifest)
        verified = verify_manifest(self.public_key, manifest, signature)
        self.assertEqual(verified["tag"], "v1.0.0-rc.2")
        tampered = manifest.replace(b"123", b"124")
        with self.assertRaisesRegex(ReleaseError, "signature verification failed"):
            verify_manifest(self.public_key, tampered, signature)

    def test_noncanonical_signed_document_is_rejected(self) -> None:
        manifest = canonical_json(sample_manifest()).replace(b",", b", ", 1)
        signature = sign_manifest(self.private_key, manifest)
        with self.assertRaisesRegex(ReleaseError, "not canonical JSON"):
            verify_manifest(self.public_key, manifest, signature)

    def test_unsafe_asset_name_is_rejected(self) -> None:
        document = sample_manifest()
        document["assets"][0]["name"] = "../client.zip"
        with self.assertRaisesRegex(ReleaseError, "asset name"):
            validate_manifest(document)

    def test_duplicate_asset_is_rejected(self) -> None:
        document = sample_manifest()
        duplicate = copy.deepcopy(document["assets"][0])
        document["assets"].append(duplicate)
        with self.assertRaisesRegex(ReleaseError, "repeats an asset"):
            validate_manifest(document)

    def test_public_key_document_preserves_fingerprint(self) -> None:
        document = public_key_document(self.public_key)
        self.assertRegex(document["fingerprint_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(document["algorithm"], "RSA-4096-SHA256-PKCS1v15")


if __name__ == "__main__":
    unittest.main()
