# ASL Agent Onboarding and Path Handoff

**Status:** Local setup, MCP bootstrap, resumable first-device chain onboarding,
finality-gated directory installation, and typed DHT directory publication are
implemented. Live deployment and installer host handoff remain external
verification work.

## Goal

Make a fresh ASL install understandable to both a person and an Agent without either guessing data paths, while keeping public-chain identity verification mandatory before the node is considered network-ready.

## Product contract

- A person runs one installer command, selects or accepts a validated local data directory once, and chooses which local Agent host to connect.
- ASL records the exact validated profile path in the host configuration. The Agent uses the configured MCP endpoint; it never infers `ASL_HOME`, searches drives, or accepts a remote-supplied path.
- First Core start creates the protected Agent root and device keys once. This is **local identity created**, not proof of public-chain registration or network admission.
- The setup report states `local_identity_ready` and `network_status: not_evaluated`. The running Core reports versioned network readiness separately through the MCP bootstrap resource. `registration_required` denotes missing verified registration; a durable registration-pending state is reserved for the registration workflow. Only verified chain state plus the signed device directory permits `network_ready`; this does not imply that transport is running or a peer is reachable.
- Trust profiles contain a chain deployment, code hash, finalized checkpoint, and bounded beacon/execution endpoints. They are explicitly imported from a trusted source; ASL does not invent endpoints, select an unverified checkpoint, or silently fall back to another profile.
- After a trusted deployment is configured, Core can construct a registration proposal from the local root key and selected device. A local human decision or a narrowly scoped prior `identity_registration` grant is required before signing/submitting it. The Agent never chooses the chain, registry address, code hash, checkpoint, sponsor, or transaction fields.
- The first device directory is root-signed and committed only after the registration is finalized and verified by the configured light client. Registration pending, sponsor unavailable, transaction rejected, stale checkpoint, and directory unavailable remain explicit states.
- Agent-facing setup guidance is available through a versioned, structured local MCP resource/status contract. It names supported actions and current readiness, not filesystem paths or secret material.
- A human may grant the local Agent narrowly scoped setup, identity-registration, and contact-management authority. These grants do not grant file, model, group, public discovery, or contact-resource access.
- Setup is idempotent. Reopening the same profile preserves its identity; malformed, inaccessible, or conflicting profiles fail closed and are never silently replaced.

## Path and installation behavior

- The installer may use the operating system's per-user application-data location as its initial suggestion. It must resolve that location from the OS/environment at runtime; no drive letter or user name is built into the executable.
- The user can choose another local fixed NTFS directory. Reparse points, device namespaces, network shares, and paths outside the supported storage contract are rejected.
- The root `asl.exe` remains the stable host command across portable-package updates. The generated host configuration contains its absolute installed path and the exact selected profile path.
- If a host-specific configuration cannot be safely updated, ASL writes a copyable, schema-valid local configuration artifact and reports that manual host approval remains necessary. It must not silently edit another project or global host profile.
- The setup/diagnostic command and MCP status distinguish local-profile, trust-profile, chain-registration, device-directory, and network errors. `offline` is never presented as an authorization denial or successful enrollment.

## Agent contract

- The MCP server publishes a versioned `asl://agent/bootstrap-v1` resource and a read-only local status result.
- The resource explains the supported structured operations, readiness states, human authorization boundaries, and recovery path. It does not ask the Agent to inspect directories, construct shell commands from model output, or modify host configuration by itself.
- Any host setup write is a typed, local-only action with a target profile and explicit user authorization. No tool accepts an arbitrary executable, path, endpoint, chain, or checkpoint from an Agent.
- When the network is not ready, ordinary network actions return a structured readiness code with a specific next action; they do not masquerade as a successful query.

## Compatibility and limits

- Existing profile directories and protected identities are retained.
- The local `AgentId` and contact identity format do not change.
- Existing `mcp --home <absolute path>` remains supported. New setup commands are additive and the package root entry forwards them to the active release.
- A signed network profile can simplify selection, but it does not replace public-chain registration. Until a trusted profile, registry deployment, and registration path are available, a new install can be locally initialized but not truthfully advertised as publicly reachable.
- Chain registration may use an explicitly selected volunteer sponsor or an authorized local transaction path; sponsor selection is not an ASL fee, account, balance, or purchase feature. No sponsor or endpoint is silently trusted.
- `asl-core --identity-registration onboard` reads
  `state/identity-onboarding-v1.json`, selects register/update from finalized
  registry state, persists the signed request, submits through the configured
  sponsor/self-pay/fallback order, waits for finality, installs the directory,
  and publishes it to the typed DHT key. Resumption uses the same durable state.
- The self-pay adapter executes an explicitly configured external local signer.
  The protected root key is never passed to a sponsor, MCP tool, command-line
  argument, or repository file. Receipts alone are not readiness.
- A finalized revocation emits `identity.finalized_revocation_v1` as the local
  hook that suspends admission while peers later refresh the verified proof.
- Installation and host configuration do not require a cloud account. Public-chain registration and P2P discovery remain unavailable when their explicitly configured network is offline.

## Acceptance

- A clean install can initialize a profile through one documented command, including when the installation and profile paths contain spaces or use a non-default local drive.
- A second invocation reuses the same identity and does not recreate keys or broaden grants.
- An unsupported or corrupt path/profile fails with a structured, actionable error and creates no fallback profile.
- Generated MCP configuration uses the exact installed root launcher and selected profile; secrets are injected only into the intended child process and are not printed or persisted in generated instructions.
- The Agent can read the bootstrap resource and distinguish local identity readiness from chain/network readiness without guessing paths.
- Registration cannot be submitted without an explicit one-time user approval or a previously granted, bounded local `identity_registration` capability; the signed intent and finalized chain proof bind the same AgentId, deployment, and device directory.
- Missing trust profile, missing registration, missing device directory, stale checkpoint, and offline chain service each remain distinguishable; none admits an unverified peer.
