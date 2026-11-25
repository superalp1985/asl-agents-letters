# ASL Friend Discovery and Consent

**Status:** Proposed for implementation

## Goal

Replace the collision-prone permanent 16-digit discovery handle with full `AgentId` identification and short-lived invitations, while letting a person authorize exactly which discovery and friend-management actions their local Agent may perform.

## Identity and discovery

- The canonical stable user code is the complete 32-byte `AgentId` in its existing canonical Base58 representation. The UI provides copy/paste, grouped visual formatting, and a QR action; formatting never changes the wire identity.
- Exact `AgentId` lookup is only allowed when the target has enabled public discoverability. It is exact-key discovery, not a name/keyword directory or proof of identity.
- Public discoverability may expose provider and network metadata to DHT participants. The UI must state this before enabling it; no public discovery is the default.
- All returned DHT providers and record values remain untrusted. A candidate is shown only after current chain state, root signature, device certificate, and authenticated `PeerId` validation.
- The legacy deterministic 16-digit short code is removed from the primary UI and is no longer published by new releases. Existing bound contacts and permissions survive migration. Existing protocol data is not silently reinterpreted as an identity or authorization.
- No device address, RPC endpoint, filesystem path, or free-form text is embedded in a discovery identifier.

## Expiring invitation

- The primary shareable invitation is generated locally, signed by the inviter's current identity root, bound to its `AgentId`, and contains a cryptographically random one-time token and mandatory expiry. The signed invitation record is stored under a domain-separated DHT key derived from the token; the record does not reveal the bearer token.
- The human chooses an expiry from fixed bounded choices (5 minutes, 15 minutes, 1 hour, or 24 hours); the protocol rejects zero expiry, expired invitations, and any lifetime above 24 hours.
- The manual temporary code is an error-checked human encoding of a 128-bit random token. The QR encodes the same versioned invitation reference. Both resolve to the identical signed DHT record; neither is an identity nor grants access. The invitation only starts a verified friend-request flow.
- Invitation consumption is single-use and persisted. Replay, wrong target, expired chain/device evidence, self-invitation, and duplicate requests fail closed. A forwarded bearer invite may initiate a request only; it cannot cause an automatic bind unless the receiver's own local policy explicitly allows that source.
- Temporary DHT records are domain-separated and bounded. They expire with the invitation and are not refreshed as a permanent handle. Queries and pending invitations use bounded per-peer and per-profile quotas.
- Exact public lookup and temporary invitation lookup use separate DHT key domains, quotas, and visibility decisions.

## Local Agent authority and friend policy

- Public discoverability, accepting friend requests, and granting contacts access are separate settings.
- A person can grant the local Agent a durable, revocable contact-management policy. The policy may allow:
  - adding an explicitly supplied full `AgentId`;
  - sending or accepting a valid expiring invitation;
  - accepting requests only from members of a specific currently active group and epoch;
  - using a recently authenticated direct interaction as a discovery/contact-request context until its configured deadline.
- Recent-interaction eligibility stores only the authenticated `AgentId`, root interaction ID, optional group ID/epoch, and expiry. It never copies the question, answer, or arbitrary text into an invite record.
- Group-specific friend-request permission is off by default. Eligibility is rechecked against the current MLS membership and epoch when the request is processed and when the local bind is committed.
- Self-add is always denied by stable `AgentId`, including another device belonging to the same Agent.
- The default inbound policy is `review`. A person may explicitly choose automatic binding for narrowly selected sources. Even then, binding only creates the local identity relationship; it does not grant resource queries, shared-directory reads, file receipt, group membership, model calls, or public disclosure.
- Contact policy expiry or revocation stops new bindings and requests. It does not erase already received data or expand any other grant.

## Protocol and migration

- Do not change ASL/1.1 frames. Add a separately versioned signed contact-invitation/discovery record and request/response protocol.
- The existing `/asl/pair/1.0.0` path remains closed; implementation must not reactivate it by accident. New messages use canonical CBOR/CDDL only and contain no prose.
- SQLite migration preserves `contact_bindings`, explicit `authorized_contacts`, group membership, and revocation state. Legacy short-code publication is disabled after upgrade; prior records are allowed to expire and are never treated as full IDs.
- Human-readable IDs, invitation tokens, DHT candidates, local contact bindings, and authorization grants remain separate types and tables.

## Acceptance

- Full `AgentId` round-trips canonically; malformed, wrong-length, noncanonical, and self IDs are rejected before network activity.
- The UI no longer offers creation/publication of a stable 16-digit code.
- A full-ID lookup returns no candidate while public discovery is disabled; when enabled, all candidates still pass the existing chain and device admission checks before display.
- Invitation QR and temporary text code decode to the identical signed payload. Expiry, replay, wrong target, tampering, same-Agent devices, and bounded-quota cases are rejected.
- Public visibility does not enable incoming requests. Group membership or an interaction does not auto-bind unless the exact local rule permits it.
- Automatic binding, when explicitly granted, never creates `authorized_contacts` or any file/group/model permission.
- A denied or revoked friend-management rule cannot be bypassed through MCP, DHT, group membership, QR import, migration, or a stale interaction.
- A test profile can complete two-Core request/approval and policy cases on loopback without a real chain. Public discovery, new registration, and cross-machine operation are recorded separately and are not inferred from loopback success.
