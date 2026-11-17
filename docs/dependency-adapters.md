# Verified Dependency Adapters

Verified on Windows with Rust 1.100.0 and the exact workspace versions in
`Cargo.toml`/`Cargo.lock`. These are compile/run observations, not a security or
cross-platform certification.

## GUI, SQLite, MCP, and utility APIs

- `eframe = 0.35.0`, `egui = 0.35.0`: `eframe::App::ui(&mut self, &mut egui::Ui, &mut eframe::Frame)`, `egui::CentralPanel::default().show(...)`, and `Context::request_repaint_after(Duration)`. The GUI probe implements the callback without opening a window.
- `rmcp = 3.10.0`: `rmcp::transport::stdio` has the function-pointer type `fn() -> (tokio::io::Stdin, tokio::io::Stdout)` with the selected `transport-io` feature. This verifies the transport entry point, not an MCP server session.
- `rusqlite = 0.43.0` with `bundled-full`: `Connection::open_in_memory`, `execute_batch`, and `query_row` successfully create/query an FTS5 table using the `unicode61` tokenizer.
- `blake3 = 1.8.7`: `blake3::hash(&[u8])` compiles in the GUI probe.
- `serde_json = 1.0.154`: serialization of a derived `Serialize` value compiles in the GUI probe.

## P2P and MLS APIs

- `libp2p = 0.57.1`: the selected `autonat`, `dcutr`, `ed25519`, `identify`, `kad`, `macros`, `mdns`, `noise`, `ping`, `quic`, `relay`, `request-response`, `tcp`, `tokio`, and `yamux` features compile together. The probe resolves `identity::Keypair::generate_ed25519`, `kad::Behaviour<kad::store::MemoryStore>`, `mdns::tokio::Behaviour`, and the selected behaviour/configuration types. It does not yet construct a `Swarm`; that belongs to T14.
- `openmls = 0.9.2`: `openmls::prelude::ProtocolVersion::Mls10` compiles. Provider, storage, credential, and group lifecycle integration remain for T31.
- `k256 = 0.14.0`: `SigningKey::from_slice`, recoverable prehash signing, `VerifyingKey::recover_from_prehash`, low-S normalization and uncompressed SEC1 public-key encoding compile and pass identity certificate tests.
- `sha3 = 0.12.0`: `Keccak256` is used for Ethereum-style root addresses, AgentId derivation and domain-separated certificate digests.
- `rand = 0.10.4`: `rngs::SysRng::try_fill_bytes` supplies fallible OS randomness for root and device key generation.
- `libp2p-identity = 0.3.1`: Ed25519 `SecretKey::try_from_bytes`, protobuf private-key encoding/decoding and PeerId derivation compile and pass device persistence tests.
- `windows = 0.62.2`: `Win32_Security_Cryptography` and `Win32_Foundation` compile for `CryptProtectData`, `CryptUnprotectData` and `LocalFree`. Windows tests exercised same-user DPAPI persistence, tamper rejection and refusal to overwrite an existing identity. Cross-user, service-account and cross-machine behavior are not validated.

Identity and DPAPI are T06 implementations, not proof of chain state. T06b now
implements local finalized-state and registry account/storage-proof verification
with Helios/Alloy. Live chain synchronization, durable verified-state caching,
device-set commitments, private IPC delivery and migration remain pending.

## Chain Verification APIs

- Official Helios 0.12.0 consensus core at revision
  `2922a475ef1b48476983333cbae7fc92fdb46cd6`: `verify_bootstrap`,
  `apply_bootstrap`, `verify_update`, `apply_update`, `verify_finality_update`
  and `apply_finality_update` compile and verify historical Mainnet fixtures on
  Windows. Only the pure consensus module is vendored, with MIT provenance;
  the full Helios client has not been compiled or adopted.
- `alloy-trie = 0.9.9`: `TrieAccount::new`, `proof::verify_proof`,
  `HashBuilder`, `ProofRetainer` and inclusion/exclusion paths compile and run.
- `alloy-primitives = 1.7.3`, `alloy-rlp = 0.3.17`,
  `alloy-consensus = 2.6.1`: fixed-width values, Keccak, RLP and
  `Header::hash_slow` compile and pass state-proof/header-binding tests.
- `alloy-provider = 2.6.1`, default features disabled:
  `ProviderBuilder::connect_mocked_client`, `Provider::get_proof` and
  `RpcWithBlock::block_id` compile/run in `probes/chain-dependencies`, with no
  RPC sent. The provider is not an application runtime dependency.
- crates.io `helios-ethereum 0.1.0` was rejected: the published package contains
  only a placeholder executable, not the upstream light-client library.

See `docs/chain-verification.md` for exact commands, checkpoint/cache lifecycle,
the upstream deprecation warning, measured Windows test-process resources and
unverified live-network boundaries.

## Probe Scope and Results

These dependencies remain in dev-dependencies until their implementation tasks
need them at runtime. Verified commands:

```text
cargo check --workspace --all-targets --locked
cargo run -p asl-app --example gui_probe --locked
cargo run -p asl-net --example transport_probe --locked
cargo run -p asl-groups --example mls_probe --locked
cargo tree --locked -e no-dev
cargo deny check licenses
```

All commands completed successfully. `cargo-deny 0.21.0` reports `licenses ok`;
it also warns about four currently unused entries in the forward-looking allow
list. `Ubuntu-font-1.0` is explicitly allowed for eframe's bundled fonts.
Third-party license notices must still be preserved in distributed packages.
