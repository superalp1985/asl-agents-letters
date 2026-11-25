CREATE TABLE mailbox_slots (
    topic_id BLOB NOT NULL CHECK(length(topic_id)=32 AND topic_id<>zeroblob(32)),
    mailbox_id BLOB NOT NULL CHECK(length(mailbox_id)=32 AND mailbox_id<>zeroblob(32)),
    envelope_hash BLOB NOT NULL CHECK(length(envelope_hash)=32 AND envelope_hash<>zeroblob(32)),
    ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 1 AND 65536),
    padded_size INTEGER NOT NULL
        CHECK(padded_size BETWEEN length(ciphertext) AND 1048576),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>created_at_ms),
    PRIMARY KEY(topic_id,mailbox_id)
) STRICT;

CREATE TABLE mailbox_shards (
    topic_id BLOB NOT NULL CHECK(length(topic_id)=32 AND topic_id<>zeroblob(32)),
    mailbox_id BLOB NOT NULL CHECK(length(mailbox_id)=32 AND mailbox_id<>zeroblob(32)),
    shard_id BLOB NOT NULL CHECK(length(shard_id)=32 AND shard_id<>zeroblob(32)),
    shard_hash BLOB NOT NULL CHECK(length(shard_hash)=32 AND shard_hash<>zeroblob(32)),
    ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 1 AND 65536),
    padded_size INTEGER NOT NULL
        CHECK(padded_size BETWEEN length(ciphertext) AND 1048576),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>created_at_ms),
    PRIMARY KEY(topic_id,mailbox_id,shard_id),
    UNIQUE(topic_id,mailbox_id,shard_hash)
) STRICT;

CREATE INDEX mailbox_slots_expiry ON mailbox_slots(expires_at_ms);
CREATE INDEX mailbox_shards_expiry ON mailbox_shards(expires_at_ms);
CREATE INDEX mailbox_shards_mailbox
ON mailbox_shards(topic_id,mailbox_id,expires_at_ms);

CREATE TABLE conversation_budget_grants (
    conversation_id TEXT NOT NULL CHECK(length(conversation_id) BETWEEN 1 AND 128),
    grant_id BLOB NOT NULL CHECK(length(grant_id)=32 AND grant_id<>zeroblob(32)),
    renewed_from BLOB CHECK(renewed_from IS NULL OR
        (length(renewed_from)=32 AND renewed_from<>zeroblob(32))),
    renewal_depth INTEGER NOT NULL CHECK(renewal_depth BETWEEN 0 AND 32),
    max_renewals INTEGER NOT NULL CHECK(max_renewals BETWEEN 0 AND 32),
    messages_granted INTEGER NOT NULL CHECK(messages_granted BETWEEN 1 AND 1000000),
    messages_consumed INTEGER NOT NULL
        CHECK(messages_consumed BETWEEN 0 AND messages_granted),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>created_at_ms),
    PRIMARY KEY(conversation_id,grant_id),
    FOREIGN KEY(conversation_id,renewed_from)
        REFERENCES conversation_budget_grants(conversation_id,grant_id),
    CHECK((renewed_from IS NULL)=(renewal_depth=0)),
    CHECK(renewal_depth<=max_renewals)
) STRICT;

CREATE INDEX conversation_budget_active
ON conversation_budget_grants(conversation_id,expires_at_ms,created_at_ms,grant_id);

CREATE TABLE conversation_act_events (
    conversation_id TEXT NOT NULL CHECK(length(conversation_id) BETWEEN 1 AND 128),
    act_id BLOB NOT NULL CHECK(length(act_id)=32 AND act_id<>zeroblob(32)),
    mls_epoch INTEGER NOT NULL CHECK(mls_epoch BETWEEN 0 AND 9223372036854775806),
    direction TEXT NOT NULL CHECK(direction IN ('in','out')),
    act_kind INTEGER NOT NULL CHECK(act_kind BETWEEN 0 AND 65535),
    causal_root BLOB NOT NULL
        CHECK(length(causal_root)=32 AND causal_root<>zeroblob(32)),
    reply_to BLOB CHECK(reply_to IS NULL OR
        (length(reply_to)=32 AND reply_to<>zeroblob(32))),
    ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 1 AND 1048576),
    padded_size INTEGER NOT NULL
        CHECK(padded_size BETWEEN length(ciphertext) AND 1048576),
    state TEXT NOT NULL CHECK(state IN ('received','processed','rejected','expired')),
    received_at_ms INTEGER NOT NULL CHECK(received_at_ms>=0),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>received_at_ms),
    PRIMARY KEY(conversation_id,act_id)
) STRICT;

CREATE INDEX conversation_act_events_expiry
ON conversation_act_events(expires_at_ms,conversation_id);
CREATE INDEX conversation_act_events_reply
ON conversation_act_events(conversation_id,reply_to)
WHERE reply_to IS NOT NULL;

CREATE TABLE conversation_attachment_refs (
    conversation_id TEXT NOT NULL,
    act_id BLOB NOT NULL,
    attachment_id BLOB NOT NULL
        CHECK(length(attachment_id)=32 AND attachment_id<>zeroblob(32)),
    blob_ref TEXT NOT NULL CHECK(length(blob_ref) BETWEEN 1 AND 512),
    plaintext_size INTEGER NOT NULL CHECK(plaintext_size BETWEEN 0 AND 9223372036854775807),
    state TEXT NOT NULL
        CHECK(state IN ('referenced','offered','authorized','complete','rejected','expired')),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>created_at_ms),
    PRIMARY KEY(conversation_id,act_id,attachment_id),
    FOREIGN KEY(conversation_id,act_id)
        REFERENCES conversation_act_events(conversation_id,act_id) ON DELETE CASCADE
) STRICT;

CREATE INDEX conversation_attachment_refs_expiry
ON conversation_attachment_refs(expires_at_ms,conversation_id);

CREATE TABLE gossip_topic_state (
    topic_id BLOB PRIMARY KEY
        CHECK(length(topic_id)=32 AND topic_id<>zeroblob(32)),
    group_binding BLOB NOT NULL
        CHECK(length(group_binding)=32 AND group_binding<>zeroblob(32)),
    group_epoch INTEGER NOT NULL CHECK(group_epoch BETWEEN 0 AND 9223372036854775806),
    rotation_seq INTEGER NOT NULL CHECK(rotation_seq BETWEEN 0 AND 9223372036854775806),
    mesh_peer_count INTEGER NOT NULL CHECK(mesh_peer_count BETWEEN 0 AND 1000000),
    mesh_health_bps INTEGER NOT NULL CHECK(mesh_health_bps BETWEEN 0 AND 10000),
    resource_budget_bytes INTEGER NOT NULL
        CHECK(resource_budget_bytes BETWEEN 0 AND 1099511627776),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms>=created_at_ms),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>updated_at_ms)
) STRICT;

CREATE INDEX gossip_topic_state_expiry ON gossip_topic_state(expires_at_ms);
CREATE INDEX gossip_topic_state_group
ON gossip_topic_state(group_binding,group_epoch,rotation_seq);

CREATE TABLE local_capacity_measurements (
    measurement_id INTEGER PRIMARY KEY,
    capacity_class TEXT NOT NULL
        CHECK(capacity_class IN ('small','medium','large','layered')),
    direct_members INTEGER NOT NULL CHECK(direct_members BETWEEN 0 AND 1000000),
    gossip_members INTEGER NOT NULL CHECK(gossip_members BETWEEN 0 AND 10000000),
    memory_bytes INTEGER NOT NULL CHECK(memory_bytes BETWEEN 0 AND 1099511627776),
    cpu_score INTEGER NOT NULL CHECK(cpu_score BETWEEN 0 AND 1000000),
    network_bps INTEGER NOT NULL CHECK(network_bps BETWEEN 0 AND 1099511627776),
    parameters_cbor BLOB NOT NULL CHECK(length(parameters_cbor) BETWEEN 1 AND 65536),
    measured_at_ms INTEGER NOT NULL CHECK(measured_at_ms>=0)
) STRICT;

CREATE INDEX local_capacity_measurements_recent
ON local_capacity_measurements(measured_at_ms DESC,measurement_id DESC);
