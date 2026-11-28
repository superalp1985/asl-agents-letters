# ASL release signing and bootstrap

ASL release metadata uses one canonical JSON manifest signed with an external
RSA-4096 key. The private key never enters the repository. The committed public
key is in `release-public-key.json`, and the same key is embedded in the
Windows PowerShell and Linux bootstrap executables.

Current public-key SHA-256:

```text
64eb7bb441ba5f82981792cf3ce0c85e5a48ee33d47ef5f92da450ce4c61d119
```

This fingerprint must be published independently of a downloaded release
artifact. A manifest and signature stored beside an artifact prove only that
they belong together, not who published them.

## Create a release manifest

```powershell
python scripts/release_manifest.py create `
  --private-key '<external-private-key.pem>' `
  --public-key packaging/release/release-public-key.json `
  --tag v1.0.0-rc.2 `
  --version 1.0.0 `
  --commit '<40-character-commit>' `
  --output '<external-release-directory>/asl-release-manifest.json' `
  --asset '<external-release-directory>/asl-bootstrap-windows-x86_64.ps1' `
  --asset '<external-release-directory>/asl-bootstrap-linux-x86_64' `
  --asset '<external-release-directory>/asl-windows-client.zip' `
  --asset '<external-release-directory>/asl-client-linux.tar.gz' `
  --asset '<external-release-directory>/asl-client.deb'
```

The command writes `asl-release-manifest.json` and
`asl-release-manifest.json.sig`. It verifies the signature before publishing
the files.

## Verify

```powershell
python scripts/release_manifest.py verify `
  --public-key packaging/release/release-public-key.json `
  --manifest '<release-directory>/asl-release-manifest.json' `
  --signature '<release-directory>/asl-release-manifest.json.sig'
```

## Bootstrap behavior

- Windows uses a PowerShell script, not an unsigned PyInstaller EXE. It verifies
  the signed manifest, verifies the client ZIP SHA-256, removes Mark-of-the-Web
  from extracted package files, and starts the existing portable client.
- Linux uses a PyInstaller bootstrap. It verifies the signed manifest and
  client tar SHA-256, then calls the packaged `install.sh`.
- The running bootstrap hash must match the signed manifest.
- Network and extraction code accepts only bounded regular files, rejects path
  traversal and symlinks, and verifies the complete archive checksum first.

Without a trusted Authenticode certificate, Windows SmartScreen cannot identify
the publisher. The PowerShell bootstrap avoids distributing another unsigned
native installer EXE; it does not replace Authenticode and must not be described
as a signed Windows application.
