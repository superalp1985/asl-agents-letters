# Structured Semantic Contexts

## Goal and honest boundary

ASL agents should be able to exchange any *finite, formally representable*
meaning without natural-language wire fields, and should detect when they do
not share the required semantics. This is not a promise that every human idea
can be translated into an unambiguous finite expression, nor that a model
cannot misunderstand a correct expression.

The achievable guarantee is narrower and testable: shared primitive meanings,
versioned concept definitions, and published conformance vectors have stable
identities and machine-checkable structure. Unknown, conflicting, or
unverified meanings remain unresolved instead of being silently guessed.

## Existing behavior

ASL/1.1 expression letters provide bounded terms, qualified concept references,
and `meaning` / `meaning_is`. A codec validates syntax and scope; it does not
install definitions, evaluate arbitrary terms, or establish that a peer's
definition is correct. `AgentId` in a concept qualifier identifies the
claimed namespace owner but does not authenticate that claim by itself.

The existing authenticated MCP host can send expression letters and subscribe
to in-memory inbound events. It does not retain events while offline.
`meaning_is` and small expressions remain useful for inline clarification.
Larger semantic contexts need an immutable package and the existing locally
authorized file-transfer path.

## Design

### 1. Shared semantic kernel

Publish a versioned, text-free semantic kernel that specifies the exact
interpretation of built-in numeric, Boolean, equality, tuple, conditional,
and lexical-binding operations. Evaluation is deterministic, pure, bounded by
the existing expression depth/node limits, and returns a typed result:
value, unresolved, or invalid. It cannot access time, network, files, tools,
permissions, or host state.

Do not infer semantics for an unknown qualified concept. Keep it symbolic
until a matching context is available. Definitions are descriptive data, not
programs to execute.

### 2. Immutable semantic context packages

A package is canonical integer-key CBOR with a fixed format version and:

- Namespace authority `AgentId`, namespace number, and revision.
- A digest derived from the canonical unsigned package bytes.
- Exact digests of required context dependencies.
- Sorted, unique concept IDs, arities, and closed expression definitions.
- Bounded conformance vectors: structured inputs and expected structured
  outputs for deterministic validation.
- A root-identity signature over a domain-separated canonical representation.

Packages contain no text strings, paths, URLs, arbitrary byte blobs, or
executable clauses. A package revision is immutable. A changed definition
gets a new digest and revision; it never overwrites an earlier meaning.
Validation checks shape, ownership, dependency identity, byte/node/count
budgets, signature, and conformance-vector behavior. Signature validity proves
who signed the package, not that the meaning is true.

Cross-package dependency graphs must be acyclic before a context is marked
conformance-ready. The context decoder never evaluates definitions. The later
pure evaluator detects recursive concept application and exhausts a fixed
evaluation budget by returning `unresolved`; it never recurses without bound.

The signed file is itself a canonical CBOR map containing the version, the
unsigned bundle as a nested CBOR map, and a 65-byte signature. The content
digest is BLAKE3 over the canonical unsigned bundle bytes with the fixed
`ASL-SEMANTIC-CONTEXT-v1` domain. Root signing bytes use the separate
`ASL-SEMANTIC-CONTEXT-SIGN-v1` domain and bind owner, namespace, revision,
kernel revision, and the exact digest. The file decoder checks structure and
signature length only; cryptographic verification against the current chain
controller is a separate required admission step. Task 2's
`AuthenticatedSemanticContextBundle` is produced only after checking the
expected AgentId and supplied active controller address; callers must obtain
that controller from their current verified chain state. Authentication
proves the signer and immutable bytes only, not that conformance vectors have
run or that the meaning is safe to act on.

The initial package-file cap is 8 MiB total; the unsigned nested bundle is
capped at 8 MiB minus 128 bytes so the file envelope and signature fit. Each
bundle contains 1 to 4,096 concept definitions, up to 64 exact dependencies,
and 1 to 4,096 conformance vectors. Every definition must have at least one
vector. Each definition and vector expression retains the ASL expression
limits; each vector has at most 16 arguments. The unsigned canonical payload
is capped below 8 MiB to leave room for the signed file envelope.

### 3. Discovery and authorized synchronization

For a small unknown concept, retain ASL/1.1 `meaning` / `meaning_is`.
For a package-sized context, the sender identifies the exact namespace
revision and content digest in a versioned structured context exchange.
`ContextRequest` asks for one exact reference. `ContextOffer` binds that
reference, the request ID, existing content ID, exact file size, and expiry.
`ContextAgreement` binds its status to that same request ID and reference.
The actual package travels through the existing content-addressed file-transfer
pipeline; it is not embedded into a control message.

The receiver never imports a context bundle because it merely arrived. The
agent selects a notified offer, and the existing inbox grant and download mode
govern all bytes. After authorized download, it explicitly stores the exact
signed bundle as a bounded, non-executable candidate. Core rechecks the
content reference, owner signature against current verified chain state, the
complete bounded dependency graph, and every conformance vector.
`ContextAgreement` reports `conformant`, `unresolved`, or `rejected`;
`conformant` means only that those exact authenticated packages passed their
declared vectors. Reception, context status, and trust cannot grant file,
group, model, or network permissions.

An agent may answer an unavailable request with a structured `unresolved`
agreement. An outgoing `ContextExpression` carries the sorted exact context
references required by its external concepts. The codec rejects missing,
extra, duplicated, conflicting, or scope-mismatched references. Before
sending, Core authenticates and validates every required context locally. The
receiver evaluates those same references and exposes its local result with the
expression; unknown or missing contexts remain unresolved. This is not proof
that a model correctly interpreted the expression.

The initial SQLite cache stores signed bundle bytes only as untrusted
candidates. It caps a profile at 256 entries and 64 MiB total. Candidate
storage never records an authenticated/conformance-ready bit. Before each
use, the app rechecks the active controller, signature, digest, dependencies,
acyclic dependency graph, and all vectors; missing or changed dependencies
make the context unresolved.

### 4. Meaning agreement

Each expression that depends on external concepts names the exact context
digests it requires. The receiver replies with its installed/missing context
set and conformance result. Until all required digests match and the
deterministic vectors pass, the host sees the message as unresolved and must
not act on inferred meaning.

For a model-based interpretation, the host may additionally return a
structured interpretation candidate. The other agent can compare it against
the package's conformance vectors and issue a structured correction or
clarification. This is evidence of compatibility on the tested vectors, not
a proof of arbitrary model cognition; consequential operations still require
the existing local authorization checks.

## Compatibility

- ASL/1.1 frames, fields, error behavior, and the existing expression grammar
  remain unchanged.
- New context-reference, context-exchange, and digest-bound expression
  messages require both peers to advertise ASL/1 minor 2 or later. There is no
  downgrade to free text.
- ASL/1.1 peers continue current structured Query/Answer and inline
  `meaning` / `meaning_is`; they do not receive context-sync frames.
- Cached packages are keyed by full authority, namespace, revision, and digest.
  A newer package cannot mutate or silently supersede a referenced digest.
- Storage migration is additive. Old clients stop on unsupported schema as
  they do today; there is no automatic permission widening.

## Acceptance

1. Independent implementations encode identical packages as identical
   canonical bytes and digests.
2. Unknown versions, duplicate or unsorted IDs, mismatched owner/definition,
   unresolved dependencies, non-canonical encodings, excessive sizes, and
   invalid signatures fail closed.
3. Semantically equivalent packages with different bytes are not treated as
   the same revision; re-encoding is stable.
4. Valid packages and exact dependency digests survive database restart.
5. Two independent Core/MCP hosts can request a missing package, receive it
   only under existing transfer permissions, validate it, exchange
   conformance results, and then exchange an expression naming that digest.
6. Revoked contacts, changed namespace revisions, missing context, failed
   vectors, expired messages, unauthorized inboxes, and offline recipients
   do not produce a false "understood" result or side effect.
7. ASL/1.1 behavior remains covered by existing protocol vectors and
   two-host loopback tests. Public-network interoperability remains a
   separate release gate.
