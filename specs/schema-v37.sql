CREATE TABLE IF NOT EXISTS contact_invites (
    invite_id BLOB PRIMARY KEY
        CHECK(length(invite_id)=16 AND invite_id<>zeroblob(16)),
    token BLOB NOT NULL UNIQUE
        CHECK(length(token)=16 AND token<>zeroblob(16)),
    agent_id BLOB NOT NULL
        CHECK(length(agent_id)=32 AND agent_id<>zeroblob(32)),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0),
    expires_at_ms INTEGER NOT NULL CHECK(
        expires_at_ms>created_at_ms
        AND expires_at_ms-created_at_ms<=86400000
    ),
    state TEXT NOT NULL CHECK(state IN ('pending','consumed','revoked')),
    note TEXT CHECK(note IS NULL OR length(note) BETWEEN 1 AND 80),
    signature BLOB NOT NULL CHECK(length(signature)=65)
) STRICT, WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS contact_invites_agent_pending
ON contact_invites(agent_id,expires_at_ms)
WHERE state='pending';

CREATE INDEX IF NOT EXISTS contact_invites_expiry
ON contact_invites(expires_at_ms,state);

CREATE TABLE IF NOT EXISTS contact_invite_receipts (
    invite_id BLOB PRIMARY KEY
        CHECK(length(invite_id)=16 AND invite_id<>zeroblob(16)),
    token_hash BLOB NOT NULL UNIQUE
        CHECK(length(token_hash)=32 AND token_hash<>zeroblob(32)),
    consumed_at_ms INTEGER NOT NULL CHECK(consumed_at_ms>=0),
    accepted INTEGER NOT NULL CHECK(accepted IN (0,1))
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS contact_invite_prompts (
    prompt_id BLOB PRIMARY KEY
        CHECK(length(prompt_id)=16 AND prompt_id<>zeroblob(16)),
    tag TEXT NOT NULL UNIQUE CHECK(length(tag) BETWEEN 1 AND 64),
    invite_id BLOB NOT NULL UNIQUE
        CHECK(length(invite_id)=16 AND invite_id<>zeroblob(16)),
    remote_agent BLOB NOT NULL
        CHECK(length(remote_agent)=32 AND remote_agent<>zeroblob(32)),
    note TEXT NOT NULL CHECK(length(note) BETWEEN 1 AND 80),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>=0),
    state TEXT NOT NULL
        CHECK(state IN ('pending','approved','rejected','expired')),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms>=0)
) STRICT, WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS contact_invite_prompts_pending
ON contact_invite_prompts(state,expires_at_ms,tag);

CREATE TABLE IF NOT EXISTS contact_invite_actions (
    action_id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL CHECK(kind IN ('add','import','decide')),
    envelope BLOB CHECK(
        envelope IS NULL OR length(envelope) BETWEEN 1 AND 65536
    ),
    prompt_id BLOB CHECK(
        prompt_id IS NULL OR (
            length(prompt_id)=16 AND prompt_id<>zeroblob(16)
        )
    ),
    requested_at_ms INTEGER NOT NULL CHECK(requested_at_ms>=0),
    state TEXT NOT NULL
        CHECK(state IN ('queued','working','complete','failed')),
    result TEXT CHECK(result IS NULL OR length(result) BETWEEN 1 AND 512),
    CHECK(
        (kind IN ('add','import') AND envelope IS NOT NULL AND prompt_id IS NULL)
        OR
        (kind='decide' AND envelope IS NULL AND prompt_id IS NOT NULL)
    )
) STRICT;

CREATE INDEX IF NOT EXISTS contact_invite_actions_queue
ON contact_invite_actions(state,action_id);
