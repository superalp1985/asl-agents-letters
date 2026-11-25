# ASL Friend Discovery and Consent Implementation Plan

> **For agentic workers:** Execute tasks in order with `superpowers:executing-plans`. Each task is one complete, reviewable feature slice.

**Goal:** Replace stable short-code friend discovery with full-AgentId lookup and expiring signed invitations, while letting a person grant narrow, auditable Agent authority over friend management.

**Architecture:** Keep `AgentId` as the canonical stable identity. Exact lookup uses a domain-separated key derived from the full ID; ephemeral invitations use a distinct versioned signed record/request flow. Core evaluates local contact policy after chain/device admission and before binding; policy never expands file, group, model, or resource permissions.

**Tech Stack:** Existing Rust 1.100 workspace, current libp2p Kademlia, canonical CBOR/CDDL, BLAKE3 domain keys, existing secp256k1 Agent root signing, SQLite, `CoreAdmission`, egui, and an established QR encoder/decoder selected by a dependency/license probe.

**Spec:** `docs/superpowers/specs/2026-11-24-friend-discovery-and-consent.md`

## Global Constraints

- Use `cargo +1.100.0 --locked --offline`; all Cargo and test data stay on E:.
- Do not modify ASL/1.1 control frames; add a separately versioned invitation protocol and signed record format.
- Never use a shortened stable code as an identity or authentication factor.
- DHT results are untrusted hints; current chain proof, root signature, device certificate, and authenticated PeerId must be checked before a candidate is actionable.
- Self-binding is always rejected by AgentId, including another device controlled by the same Agent root.
- Friend binding, contact query access, public discoverability, file access, group membership, and MCP host access remain distinct permissions.
- Defaults: public discovery off, inbound friend requests review-only, group-origin requests off, recent-interaction reuse off.
- Any automatic bind is allowed only under an explicitly configured local policy and remains revocable.
- Do not reactivate `/asl/pair/1.0.0`; preserve legacy local bindings while disabling new legacy short-code publication.

---

### Task 1: Canonical Full-AgentId Contact Lookup

**Files:**
- Modify `crates/asl-net/src/dht.rs` with a domain-separated full-AgentId lookup key.
- Modify `crates/asl-app/src/supervisor/bindings.rs` and `crates/asl-app/src/bin/asl-core/bindings_control.rs`.
- Modify `crates/asl-app/src/ui/views.rs` for full-ID copy/paste and exact lookup.
- Add tests in `crates/asl-net/src/dht.rs`, `crates/asl-app/src/bin/asl-core/bindings_control.rs`, and contact-binding integration tests.
- Update `docs/01-product.md`, `docs/02-architecture-security.md`, `docs/03-protocol.md`, and `docs/05-agent-gui.md`.

**Interfaces:**
- Add a canonical parser/formatter for full 32-byte AgentId; parsing decodes then re-encodes to ensure canonical form.
- `asl-core --bindings lookup-agent <full AgentId>` enqueues bounded exact lookup.
- Public discovery must be independently enabled on the target before a public DHT provider can be found.
- Enabling public discovery shows a local disclosure confirmation; disabling it stops announcing the exact AgentId provider. No name/keyword search is added.
- The result enters the existing candidate-verification path; it cannot directly create a binding.

- [ ] Test canonical round-trip, wrong length, invalid Base58, noncanonical spelling, and local self-ID rejection.
- [ ] Test exact AgentId lookup key differs from identity-record and content keys by domain.
- [ ] Test lookup on network-unready/offline Core returns the existing readiness status and persists no fake candidate.
- [ ] Implement lookup while keeping existing bound contacts and authorization rows unchanged.
- [ ] Run focused DHT, contact-binding, and Core command tests.

### Task 2: Versioned Expiring Invitation

**Files:**
- Add signed invitation payload types in `crates/asl-types/src/record/` or the existing protocol module.
- Add invitation CDDL and fixed vectors under `schemas/`.
- Extend `crates/asl-net/src/dht.rs` and bounded record validation with a distinct invitation domain.
- Add Core signing, verification, expiry, one-time receipt, and target validation under `crates/asl-app/src/`.
- Add focused types, network, store migration, and two-Core tests.

**Interfaces:**
- `ContactInviteV1` binds inviter AgentId, random invite ID, 32-byte nonce, creation/expiry times, optional target AgentId, and allowed operation `request_contact`.
- A random 128-bit bearer token is shown as an error-checked temporary code. The signed invitation record is stored under a separate DHT key derived from that token and binds only the token digest; the clear token is not included in the record.
- Lifetime is mandatory and is selected only from 5 minutes, 15 minutes, 1 hour, or 24 hours.
- The QR and temporary human code encode the same versioned invitation reference and resolve to the same signed object; neither carries an alternative identity or permission format.
- DHT publication and request acceptance are separate. An invite never grants contact access by itself.

- [ ] Add canonical CDDL vectors for valid, zero-expiry, overlong lifetime, target mismatch, bad signature, replay, and noncanonical encoding.
- [ ] Add SQLite tests for a one-time receipt surviving restart and rejecting a second consumption.
- [ ] Probe an established QR library for Windows compatibility, license, and locked version; do not hand-roll QR encoding/decoding.
- [ ] Implement invitation signing/verification using the existing root-identity signing boundary and domain separation.
- [ ] Add expiry, target, self-ID, admission, and quota checks before creating a local request event.
- [ ] Run focused codec, store migration, and two-Core loopback tests.

### Task 3: Local Friend-Management Policy

**Files:**
- Add an additive SQLite migration and typed policy API under `crates/asl-store/src/contact_bindings.rs`.
- Add Core enforcement in `crates/asl-app/src/supervisor/bindings.rs` and admitted-event handling.
- Add structured Agent operations in `crates/asl-app/src/mcp/contract.rs`, `server.rs`, and `stdio.rs`.
- Add policy tests in `crates/asl-store/tests/` and `crates/asl-app/tests/`.
- Update `docs/04-storage-policy.md`, `docs/05-agent-gui.md`, and `docs/03-protocol.md`.

**Interfaces:**
- Policy fields independently control public discovery, invitation sources, group IDs allowed to originate requests, recent-interaction eligibility and its bounded TTL, and whether the local Agent may auto-bind eligible requests.
- Recent-interaction eligibility stores only verified AgentId, root task ID, optional group ID/epoch, and expiry; no query/answer payload is retained for this purpose.
- Incoming default is `review`. Agent operations return `pending_review` unless an explicit local rule permits automatic binding.
- Contact-management capability does not create or change `authorized_contacts`.

- [ ] Test every default is restrictive, agent permission cannot set policy, and revocation prevents queued automatic binds.
- [ ] Test group request is rejected after member removal or epoch change and self-AgentId is rejected across multiple device PeerIds.
- [ ] Test recent-interaction token expires and cannot be retargeted to another AgentId or task.
- [ ] Implement a single Core policy decision function used by GUI, MCP, and network paths.
- [ ] Run focused storage, policy, MCP, and loopback tests.

### Task 4: User and Agent Add-Friend Workflow

**Files:**
- Modify `crates/asl-app/src/ui/views.rs` and create focused contact/invitation UI modules.
- Add QR code rendering and user-selected QR image import using the library approved in Task 2.
- Update the Agent bootstrap resource from the onboarding plan with exact `find`, `create_invite`, and `request_contact` contracts.
- Extend `crates/asl-app/src/mcp/test_host.rs` and the two-Core contact tests.
- Update Chinese-first and English-second README sections only after the workflow is implemented and captured.

**Interfaces:**
- Contacts view shows full AgentId with copy action, exact lookup, a `Create invitation` action requiring a chosen expiry, a QR display/import action, candidate verification summary, and binding/access state as separate controls.
- MCP exposes typed local contact actions only when the corresponding user grant is present; it never accepts paths, URLs, peer addresses, or executable data from the Agent.
- Group and recent-interaction policies are configured locally, not by a received invitation.

- [ ] Test QR encode/decode round-trip against the same signed invite payload and reject altered/expired QR content.
- [ ] Test UI state for no identity, network offline, candidate found, review pending, bound without contacts access, and bound with separately authorized contacts access.
- [ ] Test an Agent can only add within its explicit policy and cannot authorize files, groups, or public discovery.
- [ ] Run focused Windows GUI unit tests, package tests, and two-Core loopback acceptance.

### Task 5: Release and Compatibility Gate

**Files:**
- Update `docs/06-implementation-plan.md`, `docs/07-testing-release.md`, `docs/windows-test-checklist.md`, and `docs/plan-validation.md`.

- [ ] Verify existing v18+ contacts and revoked bindings survive migration and old short-code publication is not re-enabled.
- [ ] Run protocol vectors, store migrations, app/MCP tests, GUI checks, strict Clippy, fmt, and `git diff --check`.
- [ ] Separate local loopback evidence from chain, public DHT, cross-machine, and logged-in Agent-host evidence.
