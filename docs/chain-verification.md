# T06b Chain Verification Core

Status on 2026-11-18: local consensus/MPT verification, bounded HTTP acquisition,
and durable SQLite recovery are implemented. HTTP and restart integration tests
use local servers with historical or synthetic fixtures. T06b remains open for
real multi-provider compatibility, authorized checkpoint renewal, background
scheduling/process limits and independent security audit. No public deployment
or live Mainnet synchronization is claimed.

## Dependency Decision

| Candidate | Actual probe | Decision |
| --- | --- | --- |
| crates.io `helios-ethereum 0.1.0` | Inspected published source: its only executable prints `Hello, world!` | Rejected as an implementation dependency |
| Official Helios `0.12.0`, revision `2922a475ef1b48476983333cbae7fc92fdb46cd6` | Consensus-core API compiled/executed on Windows; historical Mainnet bootstrap, committee updates and BLS finality verified in ASL tests | Vendor only the pure consensus module; retain MIT/source provenance |
| Alloy provider `2.6.1` | Constructed a mock-backed provider and an `eth_getProof` request bound to a block hash; no HTTP request sent | Probe only, outside the runtime workspace |
| Alloy trie `0.9.9` | Account RLP, inclusion and exclusion MPT proofs compiled/executed on Windows | Runtime verifier, MIT OR Apache-2.0 |
| Alloy primitives `1.7.3`, RLP `0.3.17`, consensus `2.6.1` | Typed integers, Keccak, account encoding and full execution-header hash binding compiled/executed | Exact runtime versions in Cargo manifests/lockfile |
| Reqwest `0.13.5`, default features disabled, native-tls/JSON | Bounded chunk reads, explicit timeout/redirect/retry policy and local HTTP integration | Runtime HTTP adapter; OS certificate verification remains enabled |
| Alloy RPC types `2.6.1` | Typed EIP-1186 responses, storage-key normalization and complete execution headers | Runtime parsing; full Alloy provider remains probe-only |

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
   The durable adapter below now retains those observations independently;
   restart of the in-memory resolver alone still discards its cache.

## HTTP Acquisition

`ChainHttpClient` accepts only locally configured endpoint sets and fixed typed
operations: checkpoint bootstrap, committee updates, finality, a hash-bound
execution header when needed, and the three registry storage paths. There is no
generic URL fetch API and no endpoint/checkpoint from peer messages. Public URLs
must use HTTPS; plain HTTP is accepted only for an explicitly allowed numeric
loopback address. Endpoint credentials are not put in Debug output or errors.
Configured prefixes and query parameters are retained across beacon requests.
`specs/chain-http.example.json` has intentionally empty endpoint lists; fill
1-4 authorized URLs in each list, using objects with `url` and
`allow_loopback_http`. It supplies no live service or trusted network defaults.

Each request has connect, read and total timeouts (100-30,000 ms), no redirects,
no implicit retries, no system proxy and no response decompression. Incremental
reads enforce 256 KiB for one beacon response and 768 KiB for hex-encoded RPC
JSON before parsing. A sync call has a shared 2-32-request budget and a
1-16-update cap. It downloads one committee update at a time, stops at the
current local period or lack of verified progress, and verifies each candidate
before persisting it. A proof lookup tries at most the four configured execution
endpoints. Invalid data can switch providers; local persistence/finality-conflict
failures stop the operation. Request elapsed time advances the supplied clock
before freshness checks.

`eth_getProof` is pinned by EIP-1898 block hash with `requireCanonical=true`,
derived only from the local finalized view. No automatic block-number fallback
is enabled. Unsupported providers fail over or return unavailable. Alloy parses
the response; local MPT/code/deployment/context verification is still mandatory.
Gloas execution headers are independently RLP-hashed before exposing a root.
Bootstrap does not pretend a stale finalized checkpoint is fresh; the durable
adapter can retain it while fetching verified updates.

These are callable adapters, not an enabled background service. Supervisor
scheduling, host-wide request/CPU budgets and Windows process limits remain later
integration work.

## Durable Recovery

`DurableIdentityResolver` owns the SQLite connection and is the runtime-facing
adapter. The original in-memory resolver remains a local validation component.
The database connection is not exposed. Chain state, observations and proof
replacement commit in one immediate transaction against the previous sealed
snapshot (compare-and-swap). Agent rows are created with schema defaults only;
contacts, grants and identity authorization are not created by verification.
Frozen schema v1 fields and migration version are unchanged.

The snapshot uses the existing current-user Windows DPAPI wrapper. It binds a
version/domain, the complete consensus/deployment/cache configuration, the
Helios store including finality-conflict state, optional hash-bound execution
header, and a digest over the chain/observation/proof rows. Restore checks DPAPI
integrity before trusting serialized consensus state, then configuration,
monotonic local time, checkpoint lifetime, row digest and execution projection.
Unexpired cached proofs are rechecked with the MPT verifier, including their
saved finalized context and observation high-water mark; expiry is recomputed
from the original proved timestamp. A replay/restart cannot renew it.
Recovery uses the current clock for all TTL checks and restores historical LRU
timestamps separately; loading an older entry cannot discard a newer valid one.

Proofs stay bounded by 128 entries/32 MiB globally, with at most 256 KiB each.
The local saved-proof envelope also obeys that cap; if its encoding would exceed
the cap, the positive result is memory-only and its observation is still saved.
Expiry and LRU choose proof eviction. Local LRU accesses are checkpointed on the
next verified write, so a crash may lose recent access ordering but cannot renew
proof validity or remove an observation.

Unregistered results remain only in the bounded in-memory TTL/LRU cache. They
create no permanent agent, observation or proof rows, and return to unknown
after restart. This avoids unbounded parent rows from queries for arbitrary
absent identities. Previously observed sequence/revocation state still rejects
a downgrade to unregistered. The lower-level store checks row consistency, not
proof semantics; network results must pass through the durable verifier.

Sequence/controller/state/revocation observations are separate from proof TTL.
They remain across eviction and restart, up to 10,000 observations per chain;
at that hard ceiling, a new observation is rejected rather than deleting
high-water marks. Older sequence/height, same-sequence state changes and reversal
of revocation fail. Observed finalized revocation stays limited even without its
short-lived proof. A verified finality conflict is sealed before returning the
error and prevents restart. Any failed seal/commit disables further positive
resolutions in that process. Failed or stale writers cannot partially replace
the last committed state.

DPAPI is a local integrity boundary, not a remote consensus source, portable
backup format or hardware monotonic counter. It does not defend against a
malicious process running as the same Windows user or replacement of the entire
database with an older valid copy. Cross-device migration and rollback-aware
backup policy remain T35 work. A mismatched deployment/checkpoint configuration,
corrupt snapshot or expired weak-subjectivity view stops recovery; it never
silently rebuilds an empty database. Authorized checkpoint renewal must preserve
observations and remains an explicit pending integration task.

## Previous Core Verification

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

## Current Acquisition And Recovery Verification

On 2026-11-18, after the cache-review fixes, Windows/Rust 1.100.0 workspace tests
passed 108 cases: 49 chain tests, 34 store tests and 25 existing tests.
Clippy with `-D warnings`,
format checking, license checking (four existing unused-allowance warnings) and
the CDDL grammar/fixed ACK vector passed. Foundry and the standalone dependency
probes were not rerun.

New tests start real loopback HTTP servers with controlled replies. They cover
endpoint prefix/query preservation, invalid-provider failover, redirects,
oversized responses with and without Content-Length, timeouts, request budgets,
JSON-RPC errors, exact local block-hash requests, malformed MPT failover, and
Gloas header hashing. Historical Mainnet bootstrap/committee/finality fixture
responses are fetched over HTTP, cryptographically verified, committed to
SQLite and restored offline.

Recovery tests reopen real E-drive SQLite databases and cover snapshot/row
tampering, changed configuration, stale/future clocks, expired checkpoint,
proof lifetime, independent high-water/revocation retention, a persistent
finality-conflict lock, failed commit downgrade, concurrent stale-writer
rejection and MPT re-verification even inside an authentic local snapshot.
Synthetic Trie/Gloas tests explicitly start after consensus validation; their
test-only state constructors are absent from application builds.

A separate read-only review of this slice found two cache issues: historical
LRU time was incorrectly used as the restore cleanup clock, and negative proofs
for unregistered identities left permanent agent rows. Recovery now separates
the current TTL clock from saved LRU time, and unregistered results stay only in
bounded memory. Two additional regressions cover out-of-time-order cache
restoration and absent-identity churn without any persistent agent rows.
The reviewer subsequently read both fixes and the regression fixtures, confirmed
the two original issues resolved and reported no substantive new issue within
that scope. The reviewer did not run tests; the workspace results above are
separate execution evidence. This scoped engineering review is not a security
audit or full product acceptance.

No test contacted a public Beacon/RPC provider. Local socket tests do not prove
independent operator compatibility, live HTTPS or deployed ASL registry
operation. This slice did not repeat the earlier memory sampling and makes no
new background resource or production-security claim.
