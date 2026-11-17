# T06b Chain Verification Core

Status on 2026-11-17: the local consensus, MPT proof and in-memory identity-cache
adapters are implemented. T06b remains open for bounded live RPC acquisition,
multiple proof-provider compatibility, durable checkpoint/cache integration,
and independent security review. No contract deployment or live synchronization
is claimed.

## Dependency Decision

| Candidate | Actual probe | Decision |
| --- | --- | --- |
| crates.io `helios-ethereum 0.1.0` | Inspected published source: its only executable prints `Hello, world!` | Rejected as an implementation dependency |
| Official Helios `0.12.0`, revision `2922a475ef1b48476983333cbae7fc92fdb46cd6` | Consensus-core API compiled/executed on Windows; historical Mainnet bootstrap, committee updates and BLS finality verified in ASL tests | Vendor only the pure consensus module; retain MIT/source provenance |
| Alloy provider `2.6.1` | Constructed a mock-backed provider and an `eth_getProof` request bound to a block hash; no HTTP request sent | Probe only, outside the runtime workspace |
| Alloy trie `0.9.9` | Account RLP, inclusion and exclusion MPT proofs compiled/executed on Windows | Runtime verifier, MIT OR Apache-2.0 |
| Alloy primitives `1.7.3`, RLP `0.3.17`, consensus `2.6.1` | Typed integers, Keccak, account encoding and full execution-header hash binding compiled/executed | Exact runtime versions in Cargo manifests/lockfile |

The standalone probe is `probes/chain-dependencies/`; it has its own lockfile
and does not add the provider to application runtime dependencies. The first
candidate combination (`alloy-rlp 0.3.13`) failed dependency resolution:
Alloy consensus 2.6.1 needs at least 0.3.14. It was replaced with 0.3.17 before
the successful probe.

`vendor/helios-consensus-core/UPSTREAM.md` records the source archive SHA-256,
revision, unchanged source files, manifest normalization and omitted upstream
git patch. Ten source files were compared byte for byte against the archive.
The full Helios EVM, RPC server, filesystem database and checkpoint fallback
fetcher are not included or claimed tested. The probe emits one upstream
`GenericArray::as_slice` deprecation warning.

## Adapter Boundaries

The version-1 interfaces live in `crates/asl-app/src/chain/`:

- `EthereumLightClient` verifies a configured checkpoint and bounded individual
  beacon API responses using Helios. It only projects the finalized store into
  `FinalizedExecution`; an optimistic header is not an identity authority.
- `IdentityProofVerifier` / `EthereumProofVerifier` check the requested AgentId,
  chain, deployment, exact finalized height/hash/state root, registry account,
  pinned deployed code hash, and all three specified storage slots.
- `IdentityResolver` / `EthereumIdentityResolver` return a verified identity or
  a limited reason. These results do not grant file, contact, group, network or
  model permissions. Device certificates and device-set commitments still need
  their later integration checks.

Configuration carries the chain ID, genesis time/root, slot duration, complete
fork schedule, checkpoint root/slot, freshness limits, registry address and
deployment-specific runtime code hash. There is no endpoint, chain deployment
address, sponsor, or network-specific checkpoint default in the adapter.
Mainnet parameters and the 2023 checkpoint appear only in historical tests.
Production remains Ethereum Mainnet according to the identity specification;
configurability is not an automatic chain fallback.

The mapping root `2`, its three-slot layout, interface version and protocol proof
limits are format constants, not deployment addresses. Proofs are capped before
RLP/MPT work: 32 nodes per path, 2 KiB per node, at most eight slot paths and a
256 KiB decoded-payload budget including reserved framing space. Registry v1
requires exactly its three distinct slot paths. The future identity stream
codec must independently enforce its original encoded-frame limit.

Registry values are decoded from verified storage, not accepted as claimed
controller/sequence/status fields. Zero values require exclusion proofs.
Malformed padding, invalid status and impossible registry state fail.

## Checkpoint And Cache Lifecycle

1. A local trusted configuration supplies a recent weak-subjectivity checkpoint.
   A beacon response must match its root and slot. RPC responses cannot replace
   that checkpoint, fork schedule or genesis root.
2. Bootstrap rejects future or expired checkpoints. The configured maximum
   age cannot exceed 14 days. Applications must supply an accurate local clock.
3. Committee/finality updates are verified before applying a candidate store.
   ASL never calls Helios `force_update`. Insufficient or invalid updates cannot
   promote an optimistic state into identity state.
4. Finalized state must also pass its separate freshness limit before an
   identity proof can be accepted. Expired weak-subjectivity state requires a
   newly trusted checkpoint rather than an automatic RPC fallback.
5. Gloas headers commit an execution block hash. If needed, the caller supplies
   a bounded full execution header; Alloy decodes/hashes it and the adapter binds
   it to that verified hash before exposing its state root. This binding has a
   unit test, not a claim of live Gloas synchronization.
6. Invalid provider data leaves the current store/cache unchanged. A verified
   conflicting finalized state disables further identity use. Optimistic
   reorganizations do not update identity state.
7. Cache age is measured from the proved execution timestamp, never receipt or
   replay time. Unknown, stale, unregistered, revoked or unavailable identities
   receive limited results. Fresh cached finalized proofs remain usable during
   a short outage until the configured expiry.
8. The in-memory cache has at most 128 identities, purges expired entries on
   insertion and evicts the least recently used entry when full. It rejects
   sequence/height rollback and reversal of revocation while the observation is
   cached. Eviction, including eviction of a revoked identity, only downgrades
   that identity to unknown; a later promotion still requires a proof against
   the currently verified finalized state. Durable contact high-water marks and
   revocation observations are not implemented by this transient cache.
   Restart currently discards it. Persisting verified checkpoints/observations,
   recovery rules and authorized checkpoint renewal remain T06b integration work.

The caller currently supplies already acquired response bytes. This adapter
caps parsing and verification input; it does not yet cap an HTTP download before
buffering, schedule retries, enforce Windows process limits or contact live RPCs.
Those boundaries must be implemented before enabling background chain access.

## Verification Scope

Fresh Windows/Rust 1.100.0 results:

```text
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
cargo fmt --manifest-path probes/chain-dependencies/Cargo.toml -- --check
cargo run --manifest-path probes/chain-dependencies/Cargo.toml --offline
cargo deny --locked check licenses
cargo deny --manifest-path probes/chain-dependencies/Cargo.toml --locked check licenses
scripts/validate-cddl.ps1
```

The workspace passed 57 tests, including 26 new chain tests. Tests distinguish:

- Historical Mainnet JSON fixtures: real Helios checkpoint, committee and BLS
  finality verification under an explicit historical clock; malformed data,
  wrong checkpoint and expiry rejection.
- Synthetic deterministic account/storage tries built with Alloy: positive and
  corrupted inclusion/exclusion proofs, code hash and deployment changes,
  slot constraints and payload limits. These are not proofs for a live ASL
  deployment.
- Local state-machine tests: optimistic reorganization isolation, conflicting
  verified finality, Gloas execution-header binding, cache age, rollback,
  revocation and bounded capacity. Some begin after consensus/proof verification
  to isolate adapter transitions; they are not consensus attack simulations.

The 26 chain tests also passed serially in a hidden Windows test process.
Observed wall time was 1.15 seconds and CPU time 1.14 seconds; sampling working
memory every 25 ms observed a maximum of 8,986,624 bytes. This is a short debug
test process measurement, not an OS peak-memory guarantee, enforced resource
limit, production synchronization profile or 72-hour runtime test.

License checking passed with four existing unused-allowance warnings. CDDL
checking covers grammar and one fixed ACK vector, not the future identity-proof
stream codec. No Foundry tests were rerun in this slice; T06a's earlier contract
results remain separately recorded. No independent security audit, real RPC
compatibility run, public deployment or complete product acceptance is claimed.

An independent read-only code review found two implementation issues: Helios
discarded same-slot finality conflicts before the adapter checked them, and
expired/negative cache entries had no eviction path. The adapter now checks
authenticated supermajority finality before applying updates, and implements
TTL/LRU cleanup. Regression tests exercise the public finality-update path,
expired negative entries and LRU replacement. This engineering review does not
replace the independent security audit required before release. The same
reviewer subsequently checked the fixes and reported both original issues
resolved, with no new substantive issue in that scoped recheck. The reviewer
did not execute the workspace tests; the command results above are the
implementation run's separate verification evidence.
