# ASL Identity Registry v1

Status: architecture decision for ASL 1.0. The Solidity implementation,
deployment address, final dependency versions, and external audit are not yet
complete. This specification does not claim blockchain identity proves a
person, a unique operator, or a benign Agent.

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
implementations. Helios is a candidate reusable Rust light client, not yet an
approved dependency: it needs an embedded-library probe, version/license
review, checkpoint lifecycle design, resource measurement, and independent
security review.

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
