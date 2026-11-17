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
- `windows = 0.62.2`: the `Win32_Storage_FileSystem` feature is enabled for the Windows target and is resolved during the workspace check. No Windows API call is validated by this probe; platform API work remains in the corresponding policy tasks.

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
