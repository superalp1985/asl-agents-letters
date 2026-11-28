DROP INDEX IF EXISTS contact_binding_actions_queue;
DROP TABLE IF EXISTS contact_binding_actions_v45;

ALTER TABLE contact_binding_actions RENAME TO contact_binding_actions_v45;

CREATE TABLE contact_binding_actions (
    action_id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL CHECK(kind IN (
        'lookup', 'approve', 'dismiss', 'revoke', 'forget',
        'publish_code', 'unpublish_code',
        'set_request_review', 'set_request_auto_accept', 'set_request_reject',
        'enable_shared_group_auto_accept', 'disable_shared_group_auto_accept',
        'set_recent_interaction_ttl'
    )),
    code INTEGER CHECK(code BETWEEN 0 AND 9999999999999999),
    agent_id BLOB CHECK(agent_id IS NULL OR length(agent_id) = 32),
    peer_id TEXT CHECK(peer_id IS NULL OR length(peer_id) BETWEEN 1 AND 175),
    requested_at_ms INTEGER NOT NULL CHECK(requested_at_ms >= 0),
    state TEXT NOT NULL CHECK(state IN ('queued', 'working', 'complete', 'failed')),
    result TEXT
) STRICT;

INSERT INTO contact_binding_actions(
    action_id,kind,code,agent_id,peer_id,requested_at_ms,state,result
)
SELECT action_id,kind,code,agent_id,peer_id,requested_at_ms,state,result
FROM contact_binding_actions_v45;

DROP TABLE contact_binding_actions_v45;

CREATE INDEX contact_binding_actions_queue
ON contact_binding_actions(state, action_id);

CREATE TABLE IF NOT EXISTS contact_interaction_evidence (
    agent_id BLOB NOT NULL CHECK(length(agent_id) = 32),
    peer_id TEXT NOT NULL CHECK(length(peer_id) BETWEEN 1 AND 175),
    interaction_id BLOB NOT NULL CHECK(length(interaction_id) = 16),
    group_id BLOB CHECK(group_id IS NULL OR length(group_id) = 32),
    group_epoch INTEGER CHECK(group_epoch IS NULL OR group_epoch >= 0),
    observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > observed_at_ms),
    PRIMARY KEY(agent_id, peer_id, interaction_id),
    CHECK((group_id IS NULL AND group_epoch IS NULL)
       OR (group_id IS NOT NULL AND group_epoch IS NOT NULL))
) STRICT, WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS contact_interaction_evidence_expiry
ON contact_interaction_evidence(expires_at_ms);
