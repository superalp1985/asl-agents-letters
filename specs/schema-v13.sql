CREATE TABLE mls_incoming_invites (
    invite_id BLOB PRIMARY KEY CHECK(length(invite_id) = 16),
    wire_group_id BLOB NOT NULL CHECK(length(wire_group_id) = 32),
    base_epoch INTEGER NOT NULL CHECK(base_epoch >= 0),
    inviter_agent_id TEXT NOT NULL,
    inviter_peer_id TEXT NOT NULL REFERENCES peers(peer_id),
    recipient_agent_id TEXT NOT NULL,
    recipient_peer_id TEXT NOT NULL REFERENCES peers(peer_id),
    shown_at_ms INTEGER NOT NULL CHECK(shown_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > shown_at_ms),
    state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending', 'approved', 'closed')),
    request_id BLOB UNIQUE CHECK(length(request_id) = 16),
    package_ref BLOB UNIQUE CHECK(length(package_ref) = 32),
    sealed_package BLOB CHECK(length(sealed_package) BETWEEN 1 AND 2097152),
    FOREIGN KEY(inviter_peer_id, inviter_agent_id) REFERENCES device_identities(peer_id, agent_id),
    FOREIGN KEY(recipient_peer_id, recipient_agent_id) REFERENCES device_identities(peer_id, agent_id),
    CHECK((request_id IS NULL) = (package_ref IS NULL)),
    CHECK((state = 'approved') = (sealed_package IS NOT NULL)),
    CHECK(state <> 'approved' OR package_ref IS NOT NULL),
    CHECK(state <> 'pending' OR package_ref IS NULL)
) STRICT;

CREATE INDEX mls_invites_prompt_time ON mls_incoming_invites(shown_at_ms);
CREATE INDEX mls_invites_agent_time ON mls_incoming_invites(inviter_agent_id, shown_at_ms);
CREATE UNIQUE INDEX mls_invites_one_approval_per_room ON mls_incoming_invites(wire_group_id)
    WHERE state = 'approved';
