-- A pending request has no image. A completed row is a local display cache,
-- not a resource, transfer grant, or proof of possession of the original.
CREATE TABLE avatar_receipts (
    owner TEXT PRIMARY KEY REFERENCES observed_remote_profiles(agent_id) ON DELETE CASCADE,
    owner_key BLOB NOT NULL CHECK(length(owner_key) = 32),
    local_agent_id TEXT NOT NULL,
    content_id BLOB NOT NULL CHECK(length(content_id) = 32),
    chain_id INTEGER NOT NULL CHECK(chain_id > 0),
    checkpoint_hash BLOB NOT NULL CHECK(length(checkpoint_hash) = 32),
    registry_sequence INTEGER NOT NULL CHECK(registry_sequence >= 1),
    profile_sequence BLOB NOT NULL CHECK(length(profile_sequence) = 8),
    request_id BLOB NOT NULL UNIQUE CHECK(length(request_id) = 16),
    requested_at_ms INTEGER NOT NULL CHECK(requested_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > requested_at_ms),
    image BLOB CHECK(image IS NULL OR length(image) BETWEEN 1 AND 65536)
) STRICT, WITHOUT ROWID;
CREATE UNIQUE INDEX avatar_receipts_one_pending ON avatar_receipts((1)) WHERE image IS NULL;

CREATE TRIGGER avatar_receipts_profile_changed AFTER UPDATE ON observed_remote_profiles
WHEN OLD.chain_id <> NEW.chain_id OR OLD.checkpoint_hash <> NEW.checkpoint_hash
  OR OLD.registry_sequence <> NEW.registry_sequence OR OLD.profile_sequence <> NEW.profile_sequence
  OR OLD.avatar_content_id IS NOT NEW.avatar_content_id OR OLD.expires_at_ms <> NEW.expires_at_ms
BEGIN
    DELETE FROM avatar_receipts WHERE owner=OLD.agent_id;
END;

CREATE TRIGGER avatar_receipts_registry_changed AFTER UPDATE ON identity_registry_states
WHEN OLD.chain_id <> NEW.chain_id OR OLD.sequence <> NEW.sequence OR OLD.status <> NEW.status
  OR OLD.controller_address <> NEW.controller_address OR OLD.state_commitment <> NEW.state_commitment
BEGIN
    DELETE FROM avatar_receipts WHERE owner=OLD.agent_id;
END;

CREATE TRIGGER avatar_receipts_registry_removed AFTER DELETE ON identity_registry_states
BEGIN
    DELETE FROM avatar_receipts WHERE owner=OLD.agent_id;
END;

CREATE TRIGGER avatar_receipts_checkpoint_changed AFTER UPDATE OF checkpoint_hash ON chain_state_cache
WHEN OLD.checkpoint_hash <> NEW.checkpoint_hash
BEGIN
    DELETE FROM avatar_receipts WHERE chain_id=OLD.chain_id;
END;

CREATE TRIGGER avatar_receipts_block_insert AFTER INSERT ON contact_bindings
WHEN NEW.state='revoked'
BEGIN
    DELETE FROM avatar_receipts WHERE owner_key=NEW.agent_id;
END;

CREATE TRIGGER avatar_receipts_block_update AFTER UPDATE OF state ON contact_bindings
WHEN NEW.state='revoked'
BEGIN
    DELETE FROM avatar_receipts WHERE owner_key=NEW.agent_id;
END;

-- Core currently stores its local identity projection in settings; also
-- invalidate on edits to the legacy durable local identity row.
CREATE TRIGGER avatar_receipts_settings_insert AFTER INSERT ON settings
WHEN NEW.key IN ('network.pause_requested.v1', 'ui.local_identity.v1')
BEGIN
    DELETE FROM avatar_receipts
    WHERE (NEW.key='network.pause_requested.v1' AND NEW.value_json='true' AND image IS NULL)
       OR (NEW.key='ui.local_identity.v1' AND local_agent_id IS NOT json_extract(NEW.value_json,'$.agent_id'));
END;

CREATE TRIGGER avatar_receipts_settings_update AFTER UPDATE OF value_json ON settings
WHEN NEW.key IN ('network.pause_requested.v1', 'ui.local_identity.v1')
BEGIN
    DELETE FROM avatar_receipts
    WHERE (NEW.key='network.pause_requested.v1' AND NEW.value_json='true' AND image IS NULL)
       OR (NEW.key='ui.local_identity.v1' AND local_agent_id IS NOT json_extract(NEW.value_json,'$.agent_id'));
END;

CREATE TRIGGER avatar_receipts_settings_delete AFTER DELETE ON settings
WHEN OLD.key='ui.local_identity.v1'
BEGIN
    DELETE FROM avatar_receipts;
END;

CREATE TRIGGER avatar_receipts_local_insert AFTER INSERT ON local_agent_identity
BEGIN
    DELETE FROM avatar_receipts WHERE local_agent_id<>NEW.agent_id;
END;

CREATE TRIGGER avatar_receipts_local_update AFTER UPDATE OF agent_id ON local_agent_identity
WHEN OLD.agent_id <> NEW.agent_id
BEGIN
    DELETE FROM avatar_receipts;
END;

CREATE TRIGGER avatar_receipts_local_delete AFTER DELETE ON local_agent_identity
BEGIN
    DELETE FROM avatar_receipts;
END;
