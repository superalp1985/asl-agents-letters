PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;

CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at_ms INTEGER NOT NULL CHECK(applied_at_ms >= 0)
) STRICT;

CREATE TABLE policy_state (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    revision INTEGER NOT NULL CHECK(revision >= 1)
) STRICT;
INSERT INTO policy_state(singleton, revision) VALUES (1, 1);

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL CHECK(json_valid(value_json)),
    updated_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE agents (
    agent_id TEXT PRIMARY KEY,
    handle_code TEXT,
    public_profile_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(public_profile_json)),
    profile_sequence INTEGER NOT NULL DEFAULT 0,
    profile_expires_ms INTEGER NOT NULL DEFAULT 0,
    first_seen_ms INTEGER NOT NULL DEFAULT 0,
    identity_state TEXT NOT NULL DEFAULT 'unverified'
        CHECK(identity_state IN ('unverified', 'verified', 'changed', 'revoked'))
) STRICT;

CREATE TABLE local_agent_identity (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    agent_id TEXT NOT NULL UNIQUE REFERENCES agents(agent_id),
    public_key_hex TEXT NOT NULL CHECK(length(public_key_hex) = 64),
    key_file_relative TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE device_identities (
    peer_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    public_key_hex TEXT NOT NULL CHECK(length(public_key_hex) = 64),
    certificate_json TEXT NOT NULL CHECK(json_valid(certificate_json)),
    certificate_serial INTEGER NOT NULL CHECK(certificate_serial >= 1),
    certificate_expires_ms INTEGER NOT NULL,
    revoked_at_ms INTEGER,
    created_at_ms INTEGER NOT NULL,
    UNIQUE(peer_id, agent_id),
    UNIQUE(agent_id, certificate_serial)
) STRICT;

CREATE TABLE local_device_identity (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    peer_id TEXT NOT NULL UNIQUE REFERENCES device_identities(peer_id),
    key_file_relative TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE peers (
    peer_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    addresses_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(addresses_json)),
    last_seen_ms INTEGER NOT NULL DEFAULT 0,
    connection_state TEXT NOT NULL DEFAULT 'offline'
        CHECK(connection_state IN ('offline', 'connecting', 'direct', 'relay')),
    FOREIGN KEY(peer_id, agent_id) REFERENCES device_identities(peer_id, agent_id)
) STRICT;

CREATE TABLE authorized_contacts (
    agent_id TEXT PRIMARY KEY REFERENCES agents(agent_id),
    authorized_at_ms INTEGER NOT NULL,
    authorization_revision INTEGER NOT NULL
) STRICT;

CREATE TABLE preferred_peers (
    agent_id TEXT PRIMARY KEY REFERENCES agents(agent_id),
    reason TEXT NOT NULL,
    last_used_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE asl_groups (
    group_id TEXT PRIMARY KEY CHECK(length(group_id) = 32),
    creator_peer_id TEXT NOT NULL REFERENCES peers(peer_id),
    local_name TEXT NOT NULL CHECK(length(local_name) <= 160),
    mls_epoch INTEGER NOT NULL DEFAULT 0 CHECK(mls_epoch >= 0),
    membership_epoch INTEGER NOT NULL DEFAULT 1 CHECK(membership_epoch >= 1),
    state TEXT NOT NULL CHECK(state IN ('active', 'needs_sync', 'left', 'removed')),
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE group_members (
    group_id TEXT NOT NULL REFERENCES asl_groups(group_id),
    peer_id TEXT NOT NULL REFERENCES peers(peer_id),
    role TEXT NOT NULL CHECK(role IN ('creator', 'member')),
    state TEXT NOT NULL CHECK(state IN ('invited', 'active', 'left', 'removed')),
    joined_at_ms INTEGER,
    PRIMARY KEY(group_id, peer_id)
) STRICT;

CREATE TABLE group_events (
    event_id TEXT PRIMARY KEY CHECK(length(event_id) = 32),
    group_id TEXT NOT NULL REFERENCES asl_groups(group_id),
    mls_epoch INTEGER NOT NULL CHECK(mls_epoch >= 0),
    sender_peer_id TEXT NOT NULL REFERENCES peers(peer_id),
    kind TEXT NOT NULL CHECK(kind IN ('application', 'commit')),
    ciphertext BLOB NOT NULL CHECK(length(ciphertext) <= 65536),
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms >= created_at_ms)
) STRICT;
CREATE INDEX group_events_expiry ON group_events(expires_at_ms);
CREATE INDEX group_events_epoch ON group_events(group_id, mls_epoch);

CREATE TABLE providers (
    provider_id TEXT PRIMARY KEY,
    endpoint TEXT NOT NULL,
    model_id TEXT NOT NULL,
    credential_ref TEXT NOT NULL,
    location TEXT NOT NULL CHECK(location IN ('local', 'remote')),
    authorized INTEGER NOT NULL DEFAULT 0 CHECK(authorized IN (0, 1)),
    timeout_ms INTEGER NOT NULL CHECK(timeout_ms BETWEEN 1000 AND 120000)
) STRICT;

CREATE TABLE grants (
    grant_id TEXT PRIMARY KEY CHECK(length(grant_id) = 32),
    root_path TEXT NOT NULL,
    volume_id TEXT NOT NULL,
    root_file_id TEXT NOT NULL,
    extensions_json TEXT NOT NULL CHECK(json_valid(extensions_json)),
    audience TEXT NOT NULL CHECK(audience IN ('public', 'contacts', 'peers', 'group')),
    group_id TEXT REFERENCES asl_groups(group_id),
    model_policy TEXT NOT NULL CHECK(model_policy IN ('never', 'local_only', 'providers')),
    model_providers_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(model_providers_json)),
    max_snapshot_bytes INTEGER NOT NULL CHECK(max_snapshot_bytes >= 0),
    epoch INTEGER NOT NULL DEFAULT 1 CHECK(epoch >= 1),
    status TEXT NOT NULL CHECK(status IN ('active', 'revoked')),
    created_at_ms INTEGER NOT NULL,
    CHECK((audience = 'group' AND group_id IS NOT NULL)
       OR (audience <> 'group' AND group_id IS NULL))
) STRICT;

CREATE TABLE grant_agents (
    grant_id TEXT NOT NULL REFERENCES grants(grant_id),
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    PRIMARY KEY(grant_id, agent_id)
) STRICT;

CREATE TABLE write_grants (
    write_grant_id TEXT PRIMARY KEY CHECK(length(write_grant_id) = 32),
    kind TEXT NOT NULL CHECK(kind IN ('inbox', 'derived', 'diagnostics')),
    root_path TEXT NOT NULL,
    max_bytes INTEGER NOT NULL CHECK(max_bytes >= 0),
    epoch INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL CHECK(status IN ('active', 'revoked'))
) STRICT;

CREATE TABLE snapshots (
    content_id TEXT PRIMARY KEY CHECK(length(content_id) = 64),
    file_hash TEXT NOT NULL CHECK(length(file_hash) = 64),
    file_size INTEGER NOT NULL CHECK(file_size BETWEEN 0 AND 68719476736),
    chunk_count INTEGER NOT NULL CHECK(chunk_count BETWEEN 0 AND 65536),
    blob_relative TEXT NOT NULL,
    manifest_relative TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('importing', 'ready', 'retired', 'corrupt')),
    created_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE resources (
    row_id INTEGER PRIMARY KEY,
    resource_key TEXT NOT NULL UNIQUE CHECK(length(resource_key) = 32),
    content_id TEXT NOT NULL REFERENCES snapshots(content_id),
    grant_id TEXT REFERENCES grants(grant_id),
    source_relative TEXT,
    source_file_id TEXT,
    origin TEXT NOT NULL CHECK(origin IN ('local', 'remote', 'derived')),
    title TEXT NOT NULL CHECK(length(title) <= 160),
    summary TEXT NOT NULL CHECK(length(summary) <= 1200),
    tags_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(tags_json)),
    label_json TEXT NOT NULL DEFAULT '{"kind":"private"}' CHECK(json_valid(label_json)),
    evidence_status TEXT NOT NULL CHECK(evidence_status IN ('source_backed', 'derived_unverified', 'verified')),
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    CHECK(origin <> 'local' OR grant_id IS NOT NULL)
) STRICT;
CREATE INDEX resources_content ON resources(content_id);
CREATE INDEX resources_grant ON resources(grant_id, active);

CREATE VIRTUAL TABLE resource_fts USING fts5(
    resource_key UNINDEXED, title_tokens, summary_tokens, body_tokens, tag_tokens,
    tokenize = 'unicode61'
);

CREATE TABLE derivation_sources (
    derived_resource_key TEXT NOT NULL REFERENCES resources(resource_key),
    source_resource_key TEXT NOT NULL REFERENCES resources(resource_key),
    PRIMARY KEY(derived_resource_key, source_resource_key),
    CHECK(derived_resource_key <> source_resource_key)
) STRICT;

CREATE TABLE tasks (
    task_id TEXT PRIMARY KEY CHECK(length(task_id) = 32),
    direction TEXT NOT NULL CHECK(direction IN ('incoming', 'outgoing', 'local')),
    agent_id TEXT REFERENCES agents(agent_id),
    peer_id TEXT REFERENCES peers(peer_id),
    query_text TEXT NOT NULL,
    audience_json TEXT NOT NULL CHECK(json_valid(audience_json)),
    state TEXT NOT NULL CHECK(state IN ('queued', 'searching', 'model', 'transferring', 'done', 'declined', 'failed', 'cancelled')),
    rounds_used INTEGER NOT NULL DEFAULT 0 CHECK(rounds_used BETWEEN 0 AND 3),
    requests_used INTEGER NOT NULL DEFAULT 0 CHECK(requests_used >= 0),
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    CHECK(expires_at_ms >= created_at_ms),
    CHECK((agent_id IS NULL AND peer_id IS NULL)
       OR (agent_id IS NOT NULL AND peer_id IS NOT NULL))
) STRICT;

CREATE TABLE messages (
    message_id TEXT PRIMARY KEY CHECK(length(message_id) = 32),
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    peer_id TEXT NOT NULL REFERENCES peers(peer_id),
    direction TEXT NOT NULL CHECK(direction IN ('in', 'out')),
    kind TEXT NOT NULL CHECK(kind IN ('query', 'answer', 'offer', 'error', 'ack')),
    body_json TEXT NOT NULL CHECK(json_valid(body_json)),
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL
) STRICT;
CREATE INDEX messages_expiry ON messages(expires_at_ms);

CREATE TABLE offers (
    offer_id TEXT PRIMARY KEY CHECK(length(offer_id) = 32),
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    peer_id TEXT NOT NULL REFERENCES peers(peer_id),
    content_id TEXT NOT NULL CHECK(length(content_id) = 64),
    metadata_json TEXT NOT NULL CHECK(json_valid(metadata_json)),
    expires_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE reservations (
    reservation_id TEXT PRIMARY KEY CHECK(length(reservation_id) = 32),
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    peer_id TEXT REFERENCES peers(peer_id),
    kind TEXT NOT NULL CHECK(kind IN ('snapshot', 'download', 'derived')),
    bytes INTEGER NOT NULL CHECK(bytes >= 0),
    state TEXT NOT NULL CHECK(state IN ('held', 'consumed', 'released')),
    progress_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE transfers (
    transfer_id TEXT PRIMARY KEY CHECK(length(transfer_id) = 32),
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    content_id TEXT NOT NULL CHECK(length(content_id) = 64),
    write_grant_id TEXT NOT NULL REFERENCES write_grants(write_grant_id),
    reservation_id TEXT NOT NULL UNIQUE REFERENCES reservations(reservation_id),
    part_relative TEXT NOT NULL,
    manifest_relative TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending', 'running', 'paused', 'verifying', 'complete', 'failed', 'cancelled')),
    durable_bytes INTEGER NOT NULL DEFAULT 0 CHECK(durable_bytes >= 0),
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE transfer_consents (
    approval_id TEXT PRIMARY KEY CHECK(length(approval_id) = 32),
    transfer_id TEXT NOT NULL UNIQUE CHECK(length(transfer_id) = 32),
    direction TEXT NOT NULL CHECK(direction IN ('upload', 'download')),
    content_id TEXT NOT NULL CHECK(length(content_id) = 64),
    source_grant_id TEXT REFERENCES grants(grant_id),
    destination_write_grant_id TEXT REFERENCES write_grants(write_grant_id),
    target_agent_id TEXT REFERENCES agents(agent_id),
    group_id TEXT REFERENCES asl_groups(group_id),
    group_epoch INTEGER,
    grant_epoch INTEGER,
    state TEXT NOT NULL CHECK(state IN ('pending', 'approved', 'denied', 'expired', 'consumed')),
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms >= created_at_ms),
    decided_at_ms INTEGER,
    CHECK((direction = 'upload' AND source_grant_id IS NOT NULL
           AND destination_write_grant_id IS NULL
           AND ((target_agent_id IS NOT NULL AND group_id IS NULL AND group_epoch IS NULL)
             OR (target_agent_id IS NULL AND group_id IS NOT NULL AND group_epoch IS NOT NULL)))
       OR (direction = 'download' AND source_grant_id IS NULL
           AND destination_write_grant_id IS NOT NULL
           AND target_agent_id IS NULL
           AND ((group_id IS NULL AND group_epoch IS NULL)
             OR (group_id IS NOT NULL AND group_epoch IS NOT NULL))))
) STRICT;

CREATE TABLE transfer_sources (
    transfer_id TEXT NOT NULL REFERENCES transfers(transfer_id),
    peer_id TEXT NOT NULL REFERENCES peers(peer_id),
    bad_hashes INTEGER NOT NULL DEFAULT 0 CHECK(bad_hashes >= 0),
    state TEXT NOT NULL CHECK(state IN ('candidate', 'active', 'unavailable', 'banned')),
    PRIMARY KEY(transfer_id, peer_id)
) STRICT;

CREATE TABLE transfer_chunks (
    transfer_id TEXT NOT NULL REFERENCES transfers(transfer_id),
    chunk_index INTEGER NOT NULL CHECK(chunk_index BETWEEN 0 AND 65535),
    state TEXT NOT NULL CHECK(state IN ('missing', 'assigned', 'durable')),
    source_peer TEXT REFERENCES peers(peer_id),
    verified_at_ms INTEGER,
    PRIMARY KEY(transfer_id, chunk_index)
) STRICT;

CREATE TABLE trust_events (
    event_id TEXT PRIMARY KEY CHECK(length(event_id) = 32),
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    device_peer_id TEXT REFERENCES peers(peer_id),
    task_id TEXT REFERENCES tasks(task_id),
    dimension TEXT NOT NULL CHECK(dimension IN ('integrity', 'availability', 'evidence', 'promise')),
    outcome TEXT NOT NULL CHECK(outcome IN ('positive', 'negative', 'neutral')),
    proof_json TEXT NOT NULL CHECK(json_valid(proof_json)),
    dedupe_key TEXT NOT NULL UNIQUE,
    created_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE contribution_events (
    event_id TEXT PRIMARY KEY CHECK(length(event_id) = 32),
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    device_peer_id TEXT REFERENCES peers(peer_id),
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    content_id TEXT NOT NULL CHECK(length(content_id) = 64),
    help_kind TEXT NOT NULL CHECK(help_kind IN ('used_file', 'used_answer')),
    proof_json TEXT NOT NULL CHECK(json_valid(proof_json)),
    created_at_ms INTEGER NOT NULL,
    UNIQUE(task_id, content_id, help_kind)
) STRICT;

CREATE TABLE outbox (
    message_id TEXT PRIMARY KEY REFERENCES messages(message_id),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 3),
    next_attempt_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE processed_requests (
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    request_id TEXT NOT NULL CHECK(length(request_id) = 32),
    expires_at_ms INTEGER NOT NULL,
    PRIMARY KEY(agent_id, request_id)
) STRICT;
CREATE INDEX processed_expiry ON processed_requests(expires_at_ms);

CREATE TABLE model_calls (
    call_id TEXT PRIMARY KEY CHECK(length(call_id) = 32),
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    provider_id TEXT NOT NULL REFERENCES providers(provider_id),
    input_characters INTEGER NOT NULL CHECK(input_characters >= 0),
    output_characters INTEGER NOT NULL CHECK(output_characters >= 0),
    result_code TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE security_events (
    sequence INTEGER PRIMARY KEY,
    code TEXT NOT NULL,
    detail_json TEXT NOT NULL CHECK(json_valid(detail_json)),
    policy_revision INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL
) STRICT;

INSERT INTO schema_migrations(version, applied_at_ms) VALUES (1, 0);
