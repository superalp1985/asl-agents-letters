CREATE TABLE conversation_act_semantic_index (
    conversation_id TEXT NOT NULL CHECK(length(conversation_id) BETWEEN 1 AND 128),
    act_id BLOB NOT NULL CHECK(length(act_id)=32 AND act_id<>zeroblob(32)),
    token_hash BLOB NOT NULL CHECK(length(token_hash)=32 AND token_hash<>zeroblob(32)),
    direction TEXT NOT NULL CHECK(direction IN ('in','out')),
    act_kind INTEGER NOT NULL CHECK(act_kind BETWEEN 0 AND 65535),
    received_at_ms INTEGER NOT NULL CHECK(received_at_ms>=0),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>received_at_ms),
    PRIMARY KEY(conversation_id,act_id,token_hash)
) STRICT;

CREATE INDEX conversation_act_semantic_index_lookup
ON conversation_act_semantic_index(token_hash,expires_at_ms,received_at_ms);

CREATE INDEX conversation_act_semantic_index_expiry
ON conversation_act_semantic_index(expires_at_ms,conversation_id);
