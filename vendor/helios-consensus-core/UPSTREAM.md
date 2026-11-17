# Helios Consensus Core

- Upstream: a16z/helios, package version 0.12.0.
- Revision: `2922a475ef1b48476983333cbae7fc92fdb46cd6`.
- Source archive: `https://codeload.github.com/a16z/helios/tar.gz/2922a475ef1b48476983333cbae7fc92fdb46cd6`.
- Archive SHA-256: `c9cc0cc11b5ecfdb6826ad095c0673cf9153759533204ac22db3ba6c43cf091e`.
- License: upstream MIT license retained as `LICENSE`.

All ten files under `src/` are copied byte for byte from
`ethereum/consensus-core/src/` at that revision. The standalone manifest replaces
workspace inheritance with the exact versions resolved by the Windows API
probe. It also supplies upstream repository/license metadata. No consensus,
signature, SSZ, or Merkle-verification source is changed.

The upstream repository's optional git patch for `ethereum_hashing` is not used.
The probe and ASL lockfile use the registry implementations; this choice needs
independent review before release. The full Helios networking, EVM, RPC server,
fallback-checkpoint fetcher, and filesystem database are not included. ASL calls
the pure verification/apply APIs, never `force_update`, and controls byte limits,
checkpoint age and finalized-only identity use in its own adapter.

The Windows probe emitted an upstream `GenericArray::as_slice` deprecation
warning in `src/proof.rs`. It was not patched or represented as a clean audit.
