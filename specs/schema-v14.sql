CREATE TABLE mls_outgoing_invites (
    invite_id BLOB PRIMARY KEY CHECK(length(invite_id) = 16),
    wire_group_id BLOB NOT NULL REFERENCES mls_room_states(wire_group_id),
    base_epoch INTEGER NOT NULL CHECK(base_epoch >= 0),
    creator_peer_id TEXT NOT NULL REFERENCES peers(peer_id),
    recipient_agent_id TEXT NOT NULL,
    recipient_peer_id TEXT NOT NULL REFERENCES peers(peer_id),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > created_at_ms),
    request_id BLOB CHECK(length(request_id) = 16),
    package_ref BLOB CHECK(length(package_ref) = 32),
    welcome BLOB CHECK(length(welcome) BETWEEN 1 AND 65408),
    FOREIGN KEY(recipient_peer_id, recipient_agent_id) REFERENCES device_identities(peer_id, agent_id),
    CHECK((request_id IS NULL) = (package_ref IS NULL)),
    CHECK(welcome IS NULL OR request_id IS NOT NULL)
) STRICT;

CREATE INDEX mls_outgoing_invites_expiry ON mls_outgoing_invites(expires_at_ms);
CREATE UNIQUE INDEX mls_outgoing_one_per_device_epoch
    ON mls_outgoing_invites(wire_group_id, base_epoch, recipient_peer_id);

CREATE TABLE mls_consumed_key_packages (
    package_ref BLOB PRIMARY KEY CHECK(length(package_ref) = 32),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > 0)
) STRICT;

CREATE INDEX mls_consumed_key_packages_expiry ON mls_consumed_key_packages(expires_at_ms);
