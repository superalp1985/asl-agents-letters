# ASL External Deployment and Release Runbook

This runbook describes operator actions only. The repository change that added
these tools did not deploy a contract or service, sign a production artifact,
create a production key, or verify a public endpoint.

## Closure Status

Repository-side packaging, offline verification, install, upgrade, and
rollback flows are implemented at code/script level for this release plan;
this statement is not runtime test evidence. The following items
remain **external pending work** and must not be reported as implemented or
validated by repository changes:

| External prerequisite | Required evidence |
| --- | --- |
| Live identity-registry deployment | Reviewed transaction, final receipt, chain ID, deployed address, runtime-code hash, and finality record |
| Deployment funding or sponsor | Operator-approved account/sponsor policy and sufficient native gas asset |
| Real bootstrap and relay fleet | Independently operated public endpoints, firewall/NAT configuration, reachability and failover evidence |
| Windows Authenticode | Production certificate access, approved HTTPS timestamp service, and valid signatures on every shipped EXE |
| Production Ed25519 release key | Externally provisioned private key, independent raw-public-key fingerprint channel, and signed artifacts |
| Linux real-host execution | Supported Linux hosts running the actual systemd install, upgrade, failed-upgrade recovery, rollback, and data-preservation checks |

No repository tool generates a production signing/deployment key, funds an
account, selects a production RPC, or invents bootstrap/relay addresses.

## Identity Registry

`scripts/deploy-identity-registry.ps1` is dry-run by default: it does not add
Forge's `--broadcast` flag. The endpoint and account are explicit inputs; the
script contains no RPC endpoint, chain ID, or registry address.

```powershell
.\scripts\deploy-identity-registry.ps1 `
  -RpcUrl '<operator-provided RPC endpoint>' `
  -Account '<locally configured Foundry account>'
```

Review the dry-run output and the exact contract artifact before authorizing a
transaction. A real broadcast additionally requires `-Broadcast` and an
operator-supplied `-ExpectedChainId`; the script checks the endpoint's chain ID
before passing `--broadcast` to Forge. This action sends a transaction and may
spend the account's native gas asset. No script in this runbook funds an
account.

After deployment, verify the receipt's address and the independently reviewed
runtime-code hash against the intended chain:

```powershell
.\scripts\verify-identity-registry-deployment.ps1 `
  -RpcUrl '<operator-provided RPC endpoint>' `
  -RegistryAddress '<address from the deployment receipt>' `
  -ExpectedChainId <expected chain ID> `
  -ExpectedRuntimeCodeHash '<reviewed 32-byte runtime-code hash>'
```

The verifier is read-only. It checks the chain ID and runtime bytecode hash;
it does not establish finality, audit the contract, or prove the safety of the
RPC operator. The actual deployed address and runtime hash must be recorded in
the operator's deployment record, not guessed or added as a repository
default.

## Signed Network Seeds

The application reads `assets/network-seeds.json` beside its binaries. Its V1
envelope is `{ "payload": ..., "signature": ... }`; the Ed25519 signature
covers the compact UTF-8 JSON serialization of the payload in the Rust struct
field order. This is the existing runtime contract, not a new signing format.
Runtime settings must independently pin both `network_seed_public_key` as 32
raw-key bytes in hex and the matching `network_seed_network_id`.

Prepare a payload from independently operated, live bootstrap infrastructure.
It must contain V1 fields `version`, `network_id`, `generated_at_ms`,
`expires_at_ms`, and `nodes`; each node contains `operator_id`, `peer_id`,
`multiaddrs`, and `roles`. Use at least two distinct operators. Do not publish
documentation, placeholder, private, or unverified endpoints as production
seeds. The signer checks the shape, bounds, unique operators/peers, bootstrap
role, peer-ID suffix binding, and current validity interval. The application
still performs its own full multiaddr, address-policy, signature, expiry, and
peer binding checks; signing does not prove an endpoint is reachable.

Provision a dedicated Ed25519 release key through the operator's approved
secret-management process. Keep the private key outside the repository and
restrict its filesystem permissions. The tooling never generates keys:

```text
python3 scripts/network-seeds.py sign \
  --payload <operator-prepared-payload.json> \
  --private-key <external-release-key.pem> \
  --output <release-staging>/network-seeds.json \
  --public-key-output <release-staging>/network-seeds.public-key.hex

python3 scripts/network-seeds.py verify \
  --seeds <release-staging>/network-seeds.json \
  --public-key-file <release-staging>/network-seeds.public-key.hex \
  --network-id <expected-network-id>
```

The signer refuses repository-resident keys and outputs, overwrites, malformed
or stale seed payloads, and non-Ed25519 PEM keys. The printed SHA-256 is over
the raw public key. Authenticate that fingerprint independently before
pinning it. Optional seeds can be placed in a Windows release with
`-NetworkSeeds`, `-NetworkSeedPublicKey`, and `-NetworkSeedNetworkId`; the
packager verifies them and includes both the envelope and public-key hex in
the ZIP hash list. Users still configure the matching key and network ID in
their local `state/network-settings-v1.json`.

## Offline Release Verification

Linux packaging already has an offline mode when its Cargo cache is complete:

```bash
ASL_CARGO_OFFLINE=1 ./scripts/package-linux-infra.sh <release-staging>
./scripts/sign-release-artifact.sh \
  <external-release-key.pem> \
  <release-staging>/<linux-artifact.tar.gz> \
  ASL-LINUX-INFRA-RELEASE-v1 \
  <release-staging>
```

The signer refuses to overwrite existing sidecars and prints the SHA-256
fingerprint of the raw public key. Share that fingerprint through a channel
independent of the artifact, then verify without network access:

```bash
bash packaging/linux/verify-offline-release.sh \
  <linux-artifact.tar.gz> \
  <linux-artifact.tar.gz.sig> \
  <linux-artifact.tar.gz.release-key.pem> \
  <linux-artifact.tar.gz.sha256> \
  <independently-pinned-public-key-sha256>
```

Verification checks the external checksum, Ed25519 signature and key
fingerprint, then inspects the tar contents and every package-internal
SHA-256 entry. The archive inspector rejects path traversal, links, unexpected
files, duplicate entries, oversized archives, and invalid build/SBOM metadata.
Use the matching detached signature and pinned key; a checksum alone is not
publisher authentication.

For Windows, build with `-Offline`, sign the package manifest with the
dedicated release key, and supply the previous trusted Core to the signer.
The standalone verifier uses that trusted Core plus the independently pinned
raw-key fingerprint:

```powershell
.\scripts\package-windows.ps1 `
  -Offline `
  -OutputZip '<release ZIP>' `
  -AuthenticodeThumbprint '<certificate thumbprint>' `
  -SignToolPath '<signtool.exe>' `
  -TimestampUrl '<operator-approved HTTPS timestamp service>'
.\scripts\sign-windows-package.ps1 `
  -Package '<release ZIP>' `
  -Version '<release version>' `
  -ReleasePrivateKey '<external-release-key.pem>' `
  -VerifierCore '<previous-trusted-release>\asl-core.exe>'
.\scripts\verify-windows-release.ps1 `
  -Package '<release ZIP>' `
  -Manifest '<release manifest>' `
  -Signature '<manifest signature>' `
  -PublicKeyRaw '<32-byte raw public key>' `
  -TrustedKeySha256 '<independently-pinned raw-key SHA-256>' `
  -VerifierCore '<previous-trusted-release>\asl-core.exe' `
  -RequireAuthenticode `
  -ScratchRoot '<local verification scratch directory>'
```

For an official package, also pass the operator-selected certificate,
`signtool.exe`, and an approved HTTPS timestamp endpoint. These are external
inputs; the packager has no built-in certificate, key, or timestamp service.

When a trusted portable installation already contains the pinned raw key and
bootstrap Core, `-TrustedInstallRoot '<protected install root>'` can replace
the explicit `-PublicKeyRaw` and `-VerifierCore` arguments. The verifier also
uses the current trusted source layout verifier when available, then checks
the ZIP's canonical relative member list and every `SHA256SUMS.txt` entry plus
the SBOM contract while keeping the package file open. Optional
Authenticode checking uses the verifier host's local certificate and
revocation state; preserve its result as separate external evidence.

Official Windows packages additionally require valid Authenticode signatures
on every executable before ZIP creation. Offline verification cannot replace
independent key authentication, source review, reproducibility checks, or the
release acceptance matrix.

## Linux systemd Install, Upgrade, and Rollback

Verify the signed archive before first extraction or installation. The package
installer checks its internal `SHA256SUMS`, preserves existing config/state
files, and refuses to overwrite an existing service, launcher, or deployment
tool directory. It installs binaries in root-owned, versioned release
directories. systemd continues to execute the stable launcher path, which
resolves through an atomically replaced `current` symlink.

An upgrade re-verifies the detached signature and independently pinned key
fingerprint before safe extraction. It stages a new versioned binary, retains
the previous release, switches the pointer atomically, and restarts the
service only if it was active. A failed restart restores the prior pointer and
attempts to restart the old binary. Config, identity, and state directories
are not replaced or rolled back. The readiness check is systemd's active
state, not a public-network reachability check.

Custom install, config, state, release, tools, and systemd roots are resolved
at first installation and persisted in root-owned `install-layout.conf` next
to the installed release tools. Later upgrade and rollback commands reload
that file, so operators do not have to reconstruct environment overrides.

```bash
sudo /usr/local/libexec/asl-infra/upgrade.sh \
  <linux-artifact.tar.gz> \
  <linux-artifact.tar.gz.sig> \
  <linux-artifact.tar.gz.release-key.pem> \
  <linux-artifact.tar.gz.sha256> \
  <independently-pinned-public-key-sha256>

sudo /usr/local/libexec/asl-infra/rollback.sh
```

Rollback swaps the current and previous binary pointers and restarts the
service only when it was active. It deliberately does not restore config,
identity, or application state. Check release compatibility before rollback;
if a release changed persistent state incompatibly, stop and follow that
release's recovery instructions. Old version directories are retained for
operator-managed cleanup.

## Remaining External Evidence

No deployed registry address, chain transaction, funding/sponsor result,
production RPC approval, Authenticode result, production Ed25519 signature,
signed production seed set, publicly reachable bootstrap/relay, Linux systemd
run, cross-host failover, independent contract audit, or 72-hour network
result is established by these scripts or this runbook. These require
operator-controlled infrastructure and separate recorded evidence.
