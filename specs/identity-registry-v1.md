# ASL Identity Registry v1

Status: the immutable Solidity registry and fixed local Foundry test toolchain
are implemented. It has not been deployed; the deployment-specific address and
runtime code hash and independent contract audit are not complete. The local
Helios consensus and Alloy storage-proof adapters are implemented; live RPC
sync and durable checkpoint/cache integration remain incomplete. This specification does not claim blockchain
identity proves a person, a unique operator, or a benign Agent.

## Network and Contract

- Anchor on Ethereum Mainnet in the 1.0 production profile. Use an existing
  public chain; ASL will not operate a private or permissioned chain.
- Deploy one small, immutable registry contract with no owner, upgrade key,
  profile fields, or arbitrary call facility.
- Keep a versioned `IdentityRegistry` interface in the Rust code so another
  public-chain adapter can be added later without changing local AgentId,
  contacts, or migration-package structure. A different chain is not an
  automatic 1.0 fallback.
- Ethereum transactions require gas. ASL itself charges no fee and has no
  token, points market, or paid tier. The default submission path is a set of
  replaceable volunteer sponsors; the identity owner may also submit a
  transaction using externally acquired ETH. Sponsors can stop or rate-limit.

## Identity and Keys

- Each Agent has a locally generated secp256k1 identity-root key. It is not a
  custodial wallet and is never sent to a sponsor. Protect it with the local
  OS keystore; encrypted migration is explicit and user-authorized.
- Derive the stable 32-byte `AgentId` as
  `keccak256("ASL-Agent-v1" || initial_root_address)`. Root-key rotation keeps
  this AgentId and changes the registry's current controller address.
- A device has a separate libp2p key and PeerId. The current identity-root key
  signs its device certificate and current device-set state. A certificate
  alone does not grant access to files, contacts, groups, or models.
- A person may create any number of Agents and run multiple Agents. The chain
  records keys and transitions, not human uniqueness.

## On-chain State

Per AgentId, store only:

| Field | Purpose |
| --- | --- |
| `controller` | Current secp256k1 identity-root address |
| `stateCommitment` | Commitment to the versioned active-device/revocation state |
| `sequence` | Strictly increasing operation number and replay guard |
| `status` | Active or irreversibly revoked |

Operations are `register`, `updateState`, `rotateController`, and `revoke`.
Every operation is typed structured data bound to the chain ID, registry
address, AgentId, next sequence, and deadline. The contract checks the
signature, sequence, deadline, and new-controller proof of possession where
applicable. EIP-712 supplies typed hashing/domain separation, not replay
protection by itself; nonce/sequence and deadline checks are contract rules.

The v1 Solidity operation types are fixed:

```text
EIP-712 domain:
  EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)
  name = "ASL Identity Registry"
  version = "1"

Register(bytes32 agentId,bytes32 stateCommitment,uint64 sequence,uint64 deadline)
UpdateState(bytes32 agentId,bytes32 stateCommitment,uint64 sequence,uint64 deadline)
RotateController(bytes32 agentId,address newController,uint64 sequence,uint64 deadline)
AcceptController(bytes32 agentId,address oldController,address newController,uint64 sequence,uint64 deadline)
Revoke(bytes32 agentId,uint64 sequence,uint64 deadline)
```

The current controller signs every operation. A root rotation additionally
requires the new controller to sign the matching `AcceptController` statement;
both signatures bind the same AgentId, old/new controller, sequence, deadline,
chain, and registry. Registration sequence is exactly 1; all later operations
must use the previous sequence plus one. The sequence cannot overflow `u64`.
A deadline remains valid at its exact timestamp and is expired only when
`block.timestamp > deadline`. Anyone may relay a valid signature; the
transaction sender is not an identity authority.

## Solidity Artifact and Storage Layout

The implementation is in `contracts/src/IdentityRegistry.sol`. It uses
OpenZeppelin Contracts 5.5.0 ECDSA and EIP-712 implementations, pinned to
commit `fcbae5394ae8ad52d8e580a3477db99814b9d565`; `contracts/DEPENDENCIES.md`
records the source archive digest and the upstream MIT license is retained.
Foundry 1.9.0 and Solidity 0.8.24 are fixed for local tests. Build settings:
Cancun EVM, optimizer enabled for 200 runs, no IR pipeline, metadata hash and
CBOR metadata disabled.

Solidity storage layout under those exact sources and compiler settings:

| Slot | Value |
| --- | --- |
| 0 | OpenZeppelin EIP-712 long-name fallback storage (unused for the fixed short name) |
| 1 | OpenZeppelin EIP-712 long-version fallback storage (unused for the fixed short version) |
| 2 | `entries` mapping root |

For an AgentId, let `p = uint256(keccak256(abi.encode(agentId, uint256(2))))`.
The mapping value occupies:

| Slot | Offset | Value |
| --- | --- | --- |
| `p` | 0 | `controller` address |
| `p + 1` | 0 | `stateCommitment` bytes32 |
| `p + 2` | 0 | `sequence` uint64 |
| `p + 2` | 8 | `status` enum: 0 unregistered, 1 active, 2 revoked |

The Foundry storage-layout regression test reads these slots directly.
With the pinned build settings, the unpatched deployed-runtime bytecode
template has Keccak-256
`0x447a1a286b4e8947950a81fa38751eaecfe1871fdfd360f09c5505e523635961`
and runtime size 4,548 bytes. OpenZeppelin EIP-712 embeds deployment-time
immutable domain-cache values, so this template hash is not a substitute for
an on-chain deployed-code hash. Each deployment must publish its actual
runtime code hash alongside its chain ID and address; clients pin that
deployment-specific value. The source contains no RPC endpoint, chain ID, or
deployment address constant.

Reproduce from `contracts/` with Foundry 1.9.0:

```text
forge fmt --check
forge test
forge build --sizes
forge inspect IdentityRegistry storage-layout
forge inspect IdentityRegistry deployedBytecode
```

Never publish profiles, names, avatar data, network addresses, device lists,
queries, contacts, group membership, file IDs/content, trust, contribution,
local permissions, or model configuration on chain. The changing commitment
and controller address are still public metadata and may be correlated.

## Discovery and Verification

The chain proves that the current registry state is included in a finalized
chain state, subject to the chain's consensus and the client's bootstrap
checkpoint. It does not provide a routable address. DHT records map AgentId or
a short-code candidate to signed, expiring device/address records.

The client MUST verify:

1. The Ethereum light-client view is fresh and rooted in a configured trusted
   weak-subjectivity checkpoint.
2. The finalized execution state root contains the registry account and the
   requested AgentId storage slots, using an account/storage proof.
3. The registry account code hash matches the pinned deployment code hash.
4. The proved state commitment and sequence match the device-set witness and
   the root-key signature on the presented device certificate.
5. The certificate PeerId equals the PeerId authenticated by libp2p.

An RPC endpoint or indexer may withhold, delay, or corrupt a response. It is
not trusted to assert identity state; invalid proofs fail. EIP-1186 is marked
Stagnant, so proof-provider compatibility must be tested against multiple
implementations. The pure Helios 0.12.0 consensus module is now pinned at
revision `2922a475ef1b48476983333cbae7fc92fdb46cd6` after a Windows library probe.
Alloy verifies MPT account/storage proofs. Version/license provenance,
checkpoint/cache lifecycle and measured test-process resources are recorded in
`docs/chain-verification.md`. The full Helios client was not adopted. Live
provider compatibility, durable-state integration and independent security
review are still required.

## Sponsorship and Failure

- Any party can submit a correctly signed operation; the contract has no
  sponsor allowlist.
- The sponsor pays gas from its own funds and sees the submitting network
  metadata. Multiple independently operated endpoints reduce single-service
  dependence but do not remove this privacy or availability tradeoff.
- On chain/RPC failure, use only cached, locally verified finalized proofs.
  Unknown or stale identities receive the lowest resource class; no proof
  failure can broaden permissions.
- If every sponsor is unavailable, new identities remain `pending_anchor`.
  They can use explicitly allowed LAN discovery and local operation but are
  not presented as globally chain-verified. Existing cached identities remain
  usable under normal expiry rules. A user-paid submission remains optional.
- Reorganizations never authorize a new key. Positive transitions require a
  finalized proof. A locally observed valid revocation may reduce trust
  immediately, but may not be promoted to a globally finalized fact until
  verified.

## Upgrade and Recovery

The v1 registry is immutable. A future contract version has a new address and
accepts a migration authorization signed by the current root key; clients
verify the old and new proofs before switching. There is no owner override.
Loss or compromise of the root key has no central recovery path. Identity
rotation requires the current root key; rotation of device keys does not.

The secure storage, backup, and migration flow must never silently create a new
AgentId after a missing or corrupt key.

## T06a Verification Record

On 2026-11-17, the local Foundry suite passed 14 tests covering registration
and AgentId derivation, duplicate/forged/wrong-domain/wrong-chain signatures,
chain-ID changes after deployment, repeated/jumped sequences, expired
deadlines, two-key controller rotation and old-key rejection, irreversible
revocation, and the published storage slots. The runtime size and bytecode
template hash above were obtained from the same pinned build.

This record does not claim deployment, gas-cost measurement on Ethereum
Mainnet, independent security review, light-client verification, storage-proof
verification, or production readiness. An independent contract audit and a
separate deployment proposal are prerequisites for any public deployment.
