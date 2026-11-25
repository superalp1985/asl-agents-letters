# ASL Agent Onboarding Implementation Plan

> **For agentic workers:** Execute tasks in order with `superpowers:executing-plans`. Each task is one complete, reviewable feature slice.

**Goal:** Provide one-time profile initialization and an Agent-host handoff that does not require path guessing, while accurately distinguishing a local identity from a chain-anchored network identity.

**Architecture:** Keep `AppPaths` as the single validator for the profile root. Add an idempotent setup/status contract, use an OS-derived initial profile suggestion with explicit override, and generate host configuration only from the validated installed launcher and profile. Core remains the source of network-readiness status.

**Tech Stack:** Existing Rust 1.100 workspace, `AppPaths`, SQLite store, existing Windows PowerShell portable packaging, and existing stdio MCP/RMCP. No custom cryptography and no new network service.

**Spec:** `docs/superpowers/specs/2026-11-24-agent-onboarding.md`

## Global Constraints

- Run Rust commands with `cargo +1.100.0 --locked --offline`; keep Cargo, target, fixtures, and temp files on E:.
- Preserve create-once DPAPI identity behavior; never replace a corrupt identity with a new one.
- Use full absolute validated paths for local storage; never infer from the current directory or a remote/Agent value.
- Preserve the stable root `asl.exe` entry across portable updates and continue forwarding to the active release.
- Do not insert default chain IDs, registry addresses, RPC endpoints, or checkpoints.
- Local identity readiness is not network admission. Only existing chain proof and signed-directory checks can report `network_ready`.
- Setup and host configuration must not grant query, friend, file, group, model, or public-discovery capabilities implicitly.

---

### Task 1: Idempotent Local Profile Setup

**Files:**
- Modify `crates/asl-app/src/bin/asl.rs`.
- Add `crates/asl-app/src/profile_setup.rs`.
- Modify `crates/asl-app/src/lib.rs`.
- Add `crates/asl-app/tests/agent_setup.rs`.
- Extend `docs/04-storage-policy.md` and the onboarding spec with exact setup status codes.

**Interfaces:**
- `asl.exe setup [--data-directory <absolute path>] --json` initializes or reuses exactly one selected profile.
- With no override, `setup` derives the per-user suggestion from the OS local application-data location; failure to resolve or validate it is an error, never a drive or current-directory fallback.
- Existing `asl.exe mcp --home <path>` remains unchanged.

- [x] Add tests asserting a new profile creates one stable AgentId, a second setup reuses it, and malformed existing key material is refused rather than replaced.
- [x] Add tests for paths with spaces, explicit path override, and rejection of relative paths without creating the OS-default profile.
- [x] Run `cargo +1.100.0 test -p asl-app --test agent_setup --locked --offline -- --test-threads=1` and verify the missing `setup` command fails with `invalid or unsupported message`.
- [x] Implement setup as a thin frontend to existing `AppPaths`, SQLite, and create-once identity APIs; do not create a parallel path validator or a fake registration state.
- [x] Add an active-release forwarding regression to `windows_launch`; observed the expected unknown-command failure before adding the dispatcher.
- [x] Run focused tests, `cargo +1.100.0 clippy -p asl-app --all-targets --features desktop-ui --locked --offline -- -D warnings`, formatting, and diff checks.
- [x] Record that chain registration and signed-device-directory provisioning remain separate required steps if the deployment workflow is unavailable.

### Task 2: Stable Agent Bootstrap Resource

**Files:**
- Modify `crates/asl-app/src/mcp/stdio.rs`.
- Modify `crates/asl-app/src/mcp/contract.rs` and `crates/asl-app/src/mcp/server.rs` only if a typed status call is required.
- Extend `crates/asl-app/src/mcp/test_host.rs` and `crates/asl-app/tests/mcp_contract.rs`.
- Extend `docs/05-agent-gui.md` and `docs/windows-test-checklist.md`.

**Interfaces:**
- Add versioned local resource `asl://agent/bootstrap-v1` with structured fields: protocol version, available capabilities, current readiness enum, and actionable next-step enum.
- The resource never returns local filesystem paths, secret values, unchecked peer claims, or instructions to construct shell commands.
- `network_ready` is emitted only from the existing `NetworkAdmissionStatus::Active` state. Registration and device-directory-pending states are distinct from `network_profile_missing`.

- [x] Test every readiness state maps to one stable schema object and no field contains `ASL_HOME`, secret material, or an unrecognized path.
- [x] Test an unconfigured Core reports `network_profile_missing`; test that the validated synthetic chain fixture reports `network_ready`.
- [x] Run the focused MCP contract test and confirm it fails before the resource is registered.
- [x] Add the resource with stable schema/version and preserve all four current tool names and contracts.
- [x] Run MCP contract and app setup tests with `--locked --offline`.

### Task 3: First-Device Chain Registration

**Files:**
- Add a typed registration proposal/receipt path under `crates/asl-app/src/chain/`.
- Extend `crates/asl-app/src/network_identity.rs`, `crates/asl-app/src/supervisor.rs`, and Core's local control interface.
- Add an additive migration under `specs/` and `crates/asl-store/` only for durable pending-registration state that is required across restart.
- Add chain registration state-machine tests using the existing local HTTP and synthetic finalized-chain fixtures.
- Extend `specs/identity-registry-v1.md`, `docs/chain-verification.md`, and the onboarding spec.

**Interfaces:**
- Core creates a versioned, expiring registration proposal from its protected root identity, selected chain profile, and current device public key.
- Submission requires a one-time human decision or explicit local `identity_registration` capability. The Agent cannot mutate proposal fields or supply an endpoint/checkpoint.
- A transaction receipt alone is not success; only finalized state independently verified by the configured light client may advance to directory issuance/admission.
- If the target registry is not deployed/configured, status remains `network_profile_missing`; no sample or local fixture is accepted as a production network.

- [ ] Test proposal binds exact AgentId, chain ID, registry address/code hash, device commitment, nonce/sequence, and expiry.
- [ ] Test restart/replay, wrong deployment, unfinalized receipt, rejected transaction, expired proposal, and sponsor/endpoint failure remain non-ready.
- [ ] Implement signing/submission through the existing root key boundary without exposing private key bytes to MCP or Agent.
- [ ] Issue the first device certificate/directory only after finalized registration proof and verify it before reporting `network_ready`.
- [ ] Run all registration tests against local fixtures and record that live deployment is still a separate release prerequisite.

### Task 4: Generate Exact Local Host Configuration

**Files:**
- Add `packaging/windows/Configure-ASL-Agent.ps1`.
- Add or modify `packaging/windows/Install-ASL.ps1` and `packaging/windows/README.md`.
- Modify `packaging/windows/Portable-Layout.ps1` and `scripts/package-windows.ps1` to include new installer files.
- Add a Windows integration test in `crates/asl-app/tests/windows_launch.rs`.

**Interfaces:**
- Configuration generation takes an explicitly selected supported host and validated absolute install/profile paths.
- The generated MCP command is the stable install-root `asl.exe` plus `mcp --home <exact profile>`.
- The operation is preview-first. Applying it requires explicit user confirmation, preserves unrelated host configuration, and refuses to overwrite a conflicting server entry.
- Unsupported hosts receive a schema-valid configuration snippet written to a new, user-selected output file; no global configuration is silently modified.

- [ ] Test generated command/args round-trip paths containing spaces and non-default drive letters without changing separators or using a release subdirectory.
- [ ] Test an existing unrelated MCP entry is preserved and a conflicting `asl` entry is refused without overwrite.
- [ ] Implement one host adapter at a time; each adapter uses that host's documented project/local scope.
- [ ] Run the Windows integration test and package-layout verification.
- [ ] Document that host approval is separate from ASL capability grants.

### Task 5: Readiness and Setup Acceptance

**Files:**
- Extend `docs/07-testing-release.md`.
- Extend `docs/windows-test-checklist.md`.
- Extend `docs/plan-validation.md`.

- [ ] Test install/setup on a clean profile, an existing profile, an offline profile, and a profile with corrupt or missing chain trust.
- [ ] Test Core, GUI, and Agent host all refer to the same selected profile and no process selects a path from its working directory.
- [ ] Run focused setup/MCP/package tests, CDDL checks if schemas changed, `git diff --check`, and strict Clippy.
- [ ] Record local-only setup evidence separately from registry registration and public-network evidence.

## Dependency Note

This plan does not claim first-time public-chain registration is already available. If completing signed registration requires an undeployed registry, signer, or chain service, finish local setup/status/host handoff and report the registration blocker explicitly rather than marking the node online.
