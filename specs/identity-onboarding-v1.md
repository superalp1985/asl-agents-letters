# ASL Identity Onboarding v1

Status: the local orchestration and submission adapters are implemented in
`crates/asl-app/src/identity_onboarding.rs`. Live contract deployment, funded
transaction submission, and real RPC finality remain deployment verification
work, not claims made by this repository.

## Inputs

Onboarding reads these explicit local inputs:

- `state/network-identity-v1.json`: chain ID, registry deployment, runtime code
  hash, trusted checkpoint, beacon endpoints, and execution endpoints.
- `state/identity-onboarding-v1.json`: sponsor/self-pay policy, finality wait,
  and directory-publication wait. See `identity-onboarding.example.json`.
- The protected local `AgentIdentity` and `DeviceIdentity`.

No RPC URL, registry address, chain ID, signer executable, or local profile path
is built into the executable. The self-pay signer is an external local
executable. Its keystore or private key remains outside ASL and outside this
repository.

## Command

```text
asl-core --identity-registration onboard
asl-core --identity-registration resume
asl-core --identity-registration status
asl-core --identity-registration revoke-onchain <sequence> <deadline>
```

`onboard` is resumable. It persists the signed request, signed directory, phase,
transaction hash, route, and last bounded error before advancing.

## State Machine

1. Refresh the configured light client and obtain a storage proof for the local
   AgentId.
2. Select `register` sequence 1 when the registry entry is unregistered.
3. Select `update` at the current finalized sequence plus one when the entry is
   active under the local controller.
4. Generate the signed device directory and EIP-712 request without publishing
   the directory.
5. Submit through the configured sponsor, external self-pay signer, or fallback
   order.
6. Poll the configured light client until finalized registry state matches the
   exact sequence, commitment, active status, and controller.
7. Install the signed directory locally.
8. Publish that exact signed directory to the `ASL-DEVICE-DIRECTORY-v1` DHT key
   through the sandboxed Net process.
9. Report `ready_to_join` only after finalized state and DHT publication
   acknowledgement.

A transaction receipt is not sufficient. A sponsor returning a transaction
hash does not make the identity ready. Only the configured independently
verified finalized chain state can advance directory installation.

## Submission Adapters

`sponsor` sends:

```json
{
  "schema": "asl-identity-sponsor-request-v1",
  "operation": "register",
  "registry_sequence": 1,
  "request": {}
}
```

The sponsor returns either `{"transaction_hash":"0x..."}` or
`{"tx_hash":"0x..."}`. The sponsor sees network metadata but never receives the
protected root key.

`self_pay` spawns the configured executable with a canonical
`asl-self-pay-sign-v1` request on stdin. The helper returns either a signed
`raw_transaction`, which ASL submits to the configured execution endpoint, or a
`transaction_hash` if the external wallet submitted it itself. The example
signer script uses a Foundry keystore account from `ASL_WALLET_ACCOUNT`; it does
not read a private-key file from the repository.

`fallback` tries configured sponsors in order, then the configured external
self-pay adapter.

## Revocation Hook

`revoke-onchain` uses the same submission and finality path. After a finalized
revoked proof it writes `identity.finalized_revocation_v1` in the local SQLite
store with the AgentId, chain, registry, sequence, transaction hash, and the
action `suspend_admission_and_refresh_verified_proofs`. Existing chain refresh
logic then suspends local admission. This hook is the durable handoff to the
later peer propagation/refetch cycle; it does not claim immediate delivery to
offline peers.

## Failure Semantics

- Missing or invalid trust profile: no transaction is constructed.
- Sponsor unavailable or helper failure: status remains resumable with the same
  unexpired signed request.
- Expired request: the command rebuilds a proposal from a freshly verified
  registry sequence.
- Rejected transaction, stale checkpoint, or unfinalized state: not ready.
- DHT publication unavailable: the directory remains installed locally, the
  status remains `directory_installed`; a running Core retries publication, and
  `resume` can retry explicitly.
- Revoked registry state: onboarding stops and the durable revocation hook is
  emitted.
