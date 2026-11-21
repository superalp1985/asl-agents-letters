CREATE TABLE contact_bindings (
    agent_id BLOB PRIMARY KEY CHECK(length(agent_id) = 32),
    peer_id TEXT CHECK(peer_id IS NULL OR length(peer_id) BETWEEN 1 AND 175),
    state TEXT NOT NULL CHECK(state IN ('bound', 'revoked')),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0)
) STRICT, WITHOUT ROWID;

INSERT INTO contact_bindings(agent_id, peer_id, state, updated_at_ms)
SELECT agent_id, NULL, 'bound', paired_at_ms
FROM paired_contacts;

CREATE TABLE contact_binding_candidates (
    agent_id BLOB NOT NULL CHECK(length(agent_id) = 32),
    peer_id TEXT NOT NULL CHECK(length(peer_id) BETWEEN 1 AND 175),
    code INTEGER NOT NULL CHECK(code BETWEEN 0 AND 9999999999999999),
    first_seen_ms INTEGER NOT NULL CHECK(first_seen_ms >= 0),
    state TEXT NOT NULL CHECK(state IN ('pending', 'dismissed')),
    PRIMARY KEY(agent_id, peer_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX contact_binding_candidates_pending
ON contact_binding_candidates(state, first_seen_ms DESC);

CREATE TABLE contact_binding_actions (
    action_id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL CHECK(kind IN (
        'lookup', 'approve', 'dismiss', 'revoke', 'forget',
        'publish_code', 'unpublish_code'
    )),
    code INTEGER CHECK(code BETWEEN 0 AND 9999999999999999),
    agent_id BLOB CHECK(agent_id IS NULL OR length(agent_id) = 32),
    peer_id TEXT CHECK(peer_id IS NULL OR length(peer_id) BETWEEN 1 AND 175),
    requested_at_ms INTEGER NOT NULL CHECK(requested_at_ms >= 0),
    state TEXT NOT NULL CHECK(state IN ('queued', 'working', 'complete', 'failed')),
    result TEXT
) STRICT;

CREATE INDEX contact_binding_actions_queue
ON contact_binding_actions(state, action_id);

INSERT INTO settings(key, value_json, updated_at_ms)
VALUES ('ui.binding_code_public.v1', 'false', 0);
