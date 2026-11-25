# Structured Semantic Contexts Implementation Plan

> **For agentic workers:** Execute in task order. Each task is a complete feature slice with its own focused verification and review.

**Goal:** Add a text-free, versioned way for ASL agents to share structured meanings and verify that they reference the same semantic contexts.

**Architecture:** Keep ASL/1.1 unchanged. Define a deterministic semantic kernel and immutable canonical-CBOR context packages, then add a negotiated context-reference exchange. Transfer package bytes only through existing locally authorized file transfer, and keep received definitions non-executable and unable to grant permissions.

**Tech Stack:** Rust 1.100.0, existing `cbor2`, BLAKE3, k256 root identity signing, SQLite migrations, existing MCP mailbox, and existing transfer authorization. No new runtime dependency.

**Spec:** `docs/superpowers/specs/2026-11-24-structured-semantic-contexts.md`

## Global Constraints

- Preserve the frozen ASL/1.1 codec and existing MCP tool contracts.
- Wire payloads remain deterministic CBOR/CDDL with no text-string fallback.
- ASL/1.2 contextual expressions bind every external concept to a sorted exact digest reference; ASL/1.1 frames remain unchanged.
- Never execute a received definition or treat it as authorization.
- Every context package is bounded, immutable, content-addressed, and owner-signed.
- File package transfer continues to require existing local share/inbox grants.
- Trust and contribution remain ordering signals, never permission inputs.
- Store Cargo cache, target, temporary files, fixtures, and generated packages on E:.
- Use `--locked --offline` and Rust 1.100.0 for Rust verification.

---

### Task 1: Canonical Context Package

**Files:**
- Create `crates/asl-types/src/protocol/semantic_context.rs` for package types, canonical encoding/decoding, identity and bounds validation.
- Modify `crates/asl-types/src/protocol.rs` to export the module.
- Create `crates/asl-types/tests/semantic_context.rs` with public API tests and fixed vectors.
- Modify `schemas/asl-context-v1.cddl` with the package-file format.
- Create `schemas/context-vectors/` with canonical accepted and rejected packages.
- Update `docs/superpowers/specs/2026-11-24-structured-semantic-contexts.md` with exact wire limits and vector inventory.

**Interfaces:**
- `SemanticContextRef { authority: AgentId, namespace: u32, revision: u16, digest: Hash32 }`
- `SemanticContextBundle::encode_unsigned(&self) -> Result<Vec<u8>, AslError>`
- `SemanticContextBundle::decode_unsigned(bytes: &[u8]) -> Result<Self, AslError>`
- `SemanticContextBundle::context_ref(&self) -> Result<SemanticContextRef, AslError>`
- `SemanticConceptDefinition { concept_id: u32, arity: u8, definition: Expression }`
- `SemanticConformanceVector { concept_id: u32, inputs: Vec<Expression>, expected: Expression }`

- [x] Write a test that two independently assembled equivalent bundles encode to identical canonical bytes and the digest is stable.
- [x] Run only that test and confirm the missing package API causes the expected compile failure.
- [x] Add the public bundle types, sorted/unique ID validation, owner-qualified definition validation, dependency validation, and canonical encoder/decoder.
- [x] Add tests for unknown version, duplicate/unsorted concepts, wrong namespace in a definition, invalid arity, missing dependency, noncanonical CBOR, and package-size/count limits.
- [x] Run `cargo +1.100.0 test -p asl-types --all-targets --locked --offline`.
- [x] Run `cargo +1.100.0 clippy -p asl-types --all-targets --locked --offline -- -D warnings`, `cargo +1.100.0 fmt --all -- --check`, and `git diff --check`.
- [x] Review CDDL and accepted/rejected vectors with the context schema and fixed-vector validator.

### Task 2: Root-Signed Context Packages

**Files:**
- Create `crates/asl-app/src/semantic_context.rs` for signing, root/controller authentication, and an authenticated package type.
- Modify `crates/asl-app/src/lib.rs` to expose the module to internal runtime users.
- Create `crates/asl-app/tests/semantic_context.rs`.
- Extend `docs/superpowers/specs/2026-11-24-structured-semantic-contexts.md` with signing domain and trust states.

**Interfaces:**
- `SignedSemanticContextBundle { bundle: SemanticContextBundle, signature: Signature65 }`
- `sign_semantic_context(identity: &AgentIdentity, bundle: SemanticContextBundle) -> Result<SignedSemanticContextBundle, AslError>`
- `authenticate_semantic_context(signed: SignedSemanticContextBundle, expected_agent: AgentId, current_controller: [u8; 20]) -> Result<AuthenticatedSemanticContextBundle, AslError>`
- `AuthenticatedSemanticContextBundle` is constructible only by the verifier and does not imply semantic conformance.
- The supplied controller must come from the caller's current verified active-chain state.

- [x] Add failing tests for a valid root signature, changed package bytes, wrong controller, wrong AgentId, and signature replay under a different signing domain.
- [x] Implement a domain-separated signature over the exact canonical package digest and namespace metadata.
- [x] Verify signer AgentId and expected active controller before constructing the authenticated type.
- [x] Run `cargo +1.100.0 test -p asl-app --test semantic_context --locked --offline`.
- [ ] Run strict Clippy for `asl-types` and `asl-app`; record that signature review is not an independent security audit.

### Task 3: Deterministic Semantic Evaluator

**Files:**
- Implement the pure evaluator in `crates/asl-app/src/semantic_context.rs`.
- Extend `crates/asl-app/tests/semantic_context.rs` with semantic and bounded-evaluation tests.
- Extend `docs/superpowers/specs/2026-11-24-structured-semantic-contexts.md`.

**Interfaces:**
- `ConformanceReadySemanticContextBundle` can only be constructed by successful signature authentication and evaluation of every declared conformance vector against exact authenticated dependencies.
- `check_context_conformance(authenticated, dependencies) -> Result<ConformanceReadySemanticContextBundle, AslError>`
- `SemanticValue` has exact rational, boolean, concept, tuple, request, assertion, and definition forms.
- Evaluation returns `Value`, `Unresolved`, or `Invalid`; it performs no IO, model call, or side effect. Arithmetic uses checked `i128` rationals and returns `Unresolved` if an intermediate exceeds the fixed arithmetic bound.

- [x] Test every built-in operator using hand-derived integer and rational examples, including divide-by-zero and checked arithmetic overflow.
- [x] Test lexical `let` / `define` / `call` capture and confirm scope shadowing follows the ASL expression specification.
- [x] Test external concept applications resolve only through an authenticated package whose full reference digest exactly matches a declared dependency.
- [x] Test recursive concept application and the fixed step budget fail closed, never recurse indefinitely.
- [x] Test a mismatch in any conformance vector prevents construction of the conformance-ready type.
- [x] Run `cargo +1.100.0 test -p asl-app --test semantic_context --locked --offline`.
- [ ] Run strict Clippy for `asl-types` and `asl-app`.

### Task 4: Local Context Candidate Cache

**Files:**
- Add a versioned context cache to `crates/asl-store/src/semantic_context.rs`.
- Add the next additive SQLite schema migration and data tables in `crates/asl-store/src/schema.rs`.
- Add `crates/asl-store/tests/semantic_context.rs`.
- Extend `docs/04-storage-policy.md` and `docs/superpowers/specs/2026-11-24-structured-semantic-contexts.md`.

**Interfaces:**
- `Store::put_semantic_context_candidate(bytes, now_ms) -> Result<(SemanticContextRef, SemanticContextCandidateInsert), AslError>`
- `Store::semantic_context_candidate(reference) -> Result<Option<Vec<u8>>, AslError>`
- `Store::remove_semantic_context_candidate(reference) -> Result<bool, AslError>`
- Exact digest is the primary key; revision replacement never mutates an existing entry.
- A cache entry is untrusted candidate bytes. The API does not claim signature, dependency, or semantic verification; callers re-authenticate and re-run conformance when using it.
- Per profile, retain no more than 256 candidates or 64 MiB of signed package bytes. This is a cache ceiling, not permission to fetch or share data.

- [x] Test insert/read after reopen, exact digest mismatch, immutable duplicate behavior, distinct revision coexistence, quota exhaustion, and dependency loss.
- [x] Implement bounded untrusted-candidate storage with an additive SQLite migration and transactional namespace/revision immutability.
- [x] Verify migration preserves all existing rows and creates no sharing, inbox, or model grants.
- [x] Run `cargo +1.100.0 test -p asl-store --lib --test semantic_context --locked --offline -- --test-threads=1`.
- [ ] Run strict Clippy for `asl-store`.

### Task 5: Negotiated Context Exchange

**Files:**
- Add frozen ASL/1.2 `ContextRequest`, `ContextOffer`, and `ContextAgreement` frames to `crates/asl-types/src/protocol.rs` and `crates/asl-types/src/protocol/cbor.rs`.
- Add frozen ASL/1.2 `ContextExpression`, carrying exact context digests for every externally qualified concept.
- Update `schemas/asl-v1.cddl`, fixed vectors, and `crates/asl-types/tests/schema_vectors.rs`.
- Add the peer-minor capability check and admitted-session handling in `crates/asl-app/src/profile/admission.rs` and `crates/asl-app/src/supervisor/mail.rs`.
- Add MCP host commands/capability reporting in `crates/asl-app/src/mcp/contract.rs`, `grant.rs`, `server.rs`, and `stdio.rs`.
- Extend `docs/03-protocol.md`, `docs/05-agent-gui.md`, and `docs/superpowers/specs/2026-11-24-structured-semantic-contexts.md`.

**Interfaces:**
- Requests name authority, namespace, revision, and exact context digest.
- Offers bind the exact context digest and request ID to an existing file `content_id`, size, and expiry.
- Agreement reports the exact request ID, context digest, and conformance status; it does not claim the model understood untested meanings.
- Contextual expressions bind every referenced external concept scope to a sorted full digest reference and can only be sent when the local packages pass signature and conformance validation.
- Existing inbox/share grants and `authorized`/`ask` decisions gate all package bytes.

- [x] Add fixed codec vectors for request, offer, agreement and contextual expression, with structural rejection cases.
- [ ] Test unsupported peer minor and mismatched Offer binding, plus missing package, authorized receipt and agreement across two independent Core/MCP hosts on TCP loopback.
- [ ] Exercise offer expiry through the complete runtime and separately cover upload/revocation races for context transfers.
- [ ] Test that no package bytes are sent or written before the existing upload/download decision, including revocation races.
- [x] Implement new frames without changing ASL/1.1 fields or tool meanings; never downgrade to text.
- [ ] Run the focused protocol, store, MCP, and two-Core tests as one acceptance pass.

Implementation status (2026-11-25): direct `ContextExpression` send/receive is wired through MCP and Core. Sending checks the active controller, exact package reference, dependency graph, and conformance vectors; receiving reports the full CBOR frame plus a local evaluation state and acknowledges the message only under the existing answer setting. Group delivery, ContextRequest/Offer/Agreement runtime routing, authorized package transfer/import, expiry/revocation races, and two-Core acceptance remain incomplete.

### Task 6: Release Gate

**Files:**
- Extend `docs/07-testing-release.md`, `docs/windows-test-checklist.md`, and `docs/plan-validation.md`.

- [ ] Run workspace tests serially, strict Clippy, format, CDDL vectors, and package validation.
- [ ] Keep public-network, AppContainer, and user-visible tests explicitly separate and label incomplete acceptance honestly.

## Self-Review

- Coverage: package format, ownership, signature, dependencies, storage, transfer authorization, semantic evaluation, host capability negotiation, compatibility, and two-agent interoperability are assigned to Tasks 1-6.
- The authenticated wrapper proves signature, expected AgentId, and the caller-supplied active controller only. Store retains only untrusted candidate bytes and never persists an authenticated or conformance-ready flag.
- The conformance-ready wrapper requires exact dependency digests and all vectors to pass; the evaluator is pure and bounded, leaves unknown concepts unresolved, and executes no side effects.
- ASL/1.1 remains frozen, with no prose fallback for old peers.
