use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    time::{Duration, Instant},
};

use asl_net::mailbox::MailboxRecord;
use asl_store::{
    Store,
    budgets::BudgetKind,
    mailbox::{MailboxEnvelope, MailboxQuota},
};
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32},
    protocol::{GroupPacket, WireFrame, decode_frame, encode_frame},
};

use super::{NetworkCommand, Supervisor, unix_time_ms};
use crate::profile::AdmittedNetworkEvent;

const MAILBOX_EPOCH_MS: u64 = 3 * 24 * 60 * 60 * 1_000;
const MAILBOX_RETENTION_MS: u64 = 7 * 24 * 60 * 60 * 1_000;
const MAILBOX_EPOCH_LOOKBACK: u64 = 2;
const MAILBOX_SLOTS: u16 = 16;
const MAILBOX_TOPIC_DOMAIN: &[u8] = b"ASL-MAILBOX-TOPIC-v1\0";
const BATCH_MAGIC: &[u8; 8] = b"ASLMBXB1";
const BATCH_VERSION: u8 = 1;
const MAX_BATCH_HEADER_BYTES: usize = 11;
const MAX_BATCH_BYTES: usize = MailboxRecord::MAX_CIPHERTEXT_BYTES * MAILBOX_SLOTS as usize;
const PUBLISH_INTERVAL: Duration = Duration::from_secs(10 * 60);
const FETCH_INTERVAL: Duration = Duration::from_secs(10 * 60);
const LOOKUP_LIFETIME: Duration = Duration::from_secs(60);
const MAX_PENDING_LOOKUPS: usize = 64;
const MAX_PENDING_BATCHES: usize = 32;
const MAX_PUBLISH_IN_FLIGHT: usize = 8;

#[derive(Default)]
pub(super) struct MailboxWireRuntime {
    initialized: bool,
    known_senders: Vec<AgentId>,
    sender_cursor: usize,
    next_fetch: Option<Instant>,
    next_publish: Option<Instant>,
    lookups: HashMap<[u8; 16], LookupIntent>,
    lookup_started: HashMap<[u8; 16], Instant>,
    queued_lookups: VecDeque<LookupIntent>,
    publish_ops: HashMap<[u8; 16], PublishKey>,
    published: HashMap<PublishKey, Instant>,
    batches: HashMap<BatchKey, PendingBatch>,
    seen_records: HashSet<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct LookupIntent {
    sender_id: AgentId,
    epoch: u64,
    slot: u16,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct PublishKey {
    recipient_id: AgentId,
    sender_id: AgentId,
    epoch: u64,
    batch_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct BatchKey {
    sender_id: AgentId,
    epoch: u64,
    mailbox_id: [u8; 32],
}

struct PendingBatch {
    shard_count: u16,
    parts: BTreeMap<u16, Vec<u8>>,
    expires_at_ms: u64,
    received_at: Instant,
}

pub(super) struct ReassembledGroupPacket {
    pub packet: GroupPacket,
}

impl MailboxWireRuntime {
    pub(super) fn persist_group_packet(
        &mut self,
        store: &mut Store,
        room: Hash32,
        local_agent: AgentId,
        packet: &GroupPacket,
        now_ms: u64,
    ) -> Result<(), AslError> {
        let frame = encode_frame(&WireFrame::GroupEnvelope(packet.clone().into_envelope()?))?;
        if frame.is_empty() || frame.len() > 1024 * 1024 {
            return Err(AslError::InvalidMessage);
        }
        let conversation = alloy_primitives::hex::encode(room.0);
        let frame_bytes = u64::try_from(frame.len()).map_err(|_| AslError::InvalidMessage)?;
        if !store.resource_budget_available(&conversation, BudgetKind::MailboxBytes, now_ms)? {
            return Err(AslError::QuotaExceeded);
        }
        let epoch = now_ms / MAILBOX_EPOCH_MS;
        let mailbox_id = digest(b"ASL-MAILBOX-PACKET-v1\0", &frame);
        let expires_at_ms = now_ms
            .checked_add(MAILBOX_RETENTION_MS)
            .ok_or(AslError::InvalidMessage)?
            .min(i64::MAX as u64);
        let padded_size = padded_size(frame.len())?;
        for recipient_id in group_recipient_agents(store, room, local_agent)? {
            let topic_id = mailbox_topic(recipient_id, local_agent, epoch);
            store.put_mailbox_envelope(MailboxEnvelope {
                topic_id,
                mailbox_id,
                envelope_hash: mailbox_id,
                ciphertext: &frame,
                padded_size,
                now_ms: i64::try_from(now_ms).map_err(|_| AslError::InvalidMessage)?,
                expires_at_ms: i64::try_from(expires_at_ms)
                    .map_err(|_| AslError::InvalidMessage)?,
                quota: MailboxQuota {
                    max_entries: 512,
                    max_bytes: 64 * 1024 * 1024,
                },
            })?;
        }
        let _ = store.consume_resource_budget(
            &conversation,
            BudgetKind::MailboxBytes,
            frame_bytes,
            now_ms,
        );
        self.next_publish = Some(Instant::now());
        Ok(())
    }
}

impl Supervisor {
    pub(super) fn poll_mailbox_wire(&mut self) -> Result<(), AslError> {
        if !self.net.is_running()
            || self.network_admission_status != super::NetworkAdmissionStatus::Active
            || self.network_report.pause_requested()?
        {
            return Ok(());
        }
        let now_ms = unix_time_ms()?;
        let now = Instant::now();
        let local_agent = self.agent_identity.agent_id();
        let net = &self.net;
        let runtime = &mut self.mailbox_wire;
        expire_lookup_state(runtime, now);
        let fetch_due = runtime.next_fetch.is_none_or(|deadline| now >= deadline);
        let publish_due_now = runtime.next_publish.is_none_or(|deadline| now >= deadline);
        if !fetch_due
            && !publish_due_now
            && runtime.queued_lookups.is_empty()
            && runtime.lookups.is_empty()
        {
            return Ok(());
        }
        let mut store = asl_store::open_store(&self.state_database)?;
        if fetch_due {
            runtime.sender_cursor = 0;
            runtime.next_fetch = Some(now + FETCH_INTERVAL);
            runtime.initialized = false;
        }
        refresh_known_senders(runtime, &store, local_agent)?;
        if publish_due_now {
            let _ =
                store.prune_mailboxes(i64::try_from(now_ms).map_err(|_| AslError::InvalidMessage)?);
            if let Err(error) = publish_due(runtime, &store, local_agent, now_ms, |command| {
                send_mailbox_command(net, command)
            }) {
                if matches!(
                    error,
                    AslError::SandboxUnavailable | AslError::QuotaExceeded
                ) {
                    runtime.next_publish = Some(now + Duration::from_secs(30));
                    return Ok(());
                }
                return Err(error);
            }
            runtime.next_publish = Some(if runtime.publish_ops.len() >= MAX_PUBLISH_IN_FLIGHT {
                now + Duration::from_secs(30)
            } else {
                now + PUBLISH_INTERVAL
            });
        }
        if let Err(error) = schedule_lookups(
            runtime,
            now,
            now_ms / MAILBOX_EPOCH_MS,
            local_agent,
            |command| send_mailbox_command(net, command),
        ) && !matches!(
            error,
            AslError::SandboxUnavailable | AslError::QuotaExceeded
        ) {
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn observe_mailbox_operation(&mut self, event: &AdmittedNetworkEvent) {
        match event {
            AdmittedNetworkEvent::OperationAccepted { operation_id } => {
                self.mailbox_wire.lookups.remove(operation_id);
                self.mailbox_wire.lookup_started.remove(operation_id);
                if let Some(key) = self.mailbox_wire.publish_ops.remove(operation_id) {
                    self.mailbox_wire.published.insert(key, Instant::now());
                }
            }
            AdmittedNetworkEvent::OperationFailed { operation_id, .. } => {
                self.mailbox_wire.lookups.remove(operation_id);
                self.mailbox_wire.lookup_started.remove(operation_id);
                if let Some(key) = self.mailbox_wire.publish_ops.remove(operation_id) {
                    self.mailbox_wire.published.remove(&key);
                }
            }
            _ => {}
        }
    }

    pub(super) fn handle_mailbox_record(
        &mut self,
        record: &MailboxRecord,
        now_ms: u64,
    ) -> Result<Vec<ReassembledGroupPacket>, AslError> {
        let local_agent = self.agent_identity.agent_id();
        if record.recipient_id != local_agent.0
            || record.shard_count == 0
            || record.shard_count > MAILBOX_SLOTS
            || record.validate_at(now_ms).is_err()
        {
            return Err(AslError::InvalidMessage);
        }
        let sender_id = AgentId(record.sender_id);
        let current_epoch = now_ms / MAILBOX_EPOCH_MS;
        if sender_id == local_agent
            || !self.mailbox_wire.known_senders.contains(&sender_id)
            || record.epoch > current_epoch
            || current_epoch.saturating_sub(record.epoch) > MAILBOX_EPOCH_LOOKBACK
        {
            return Err(AslError::PolicyDenied);
        }
        let record_hash = record.hash()?;
        if !self.mailbox_wire.seen_records.insert(record_hash) {
            return Ok(Vec::new());
        }
        let key = BatchKey {
            sender_id,
            epoch: record.epoch,
            mailbox_id: record.mailbox_id,
        };
        if !self.mailbox_wire.batches.contains_key(&key)
            && self.mailbox_wire.batches.len() >= MAX_PENDING_BATCHES
            && let Some(oldest) = self
                .mailbox_wire
                .batches
                .iter()
                .min_by_key(|(_, batch)| batch.received_at)
                .map(|(key, _)| *key)
        {
            self.mailbox_wire.batches.remove(&oldest);
        }
        let now = Instant::now();
        let pending = self
            .mailbox_wire
            .batches
            .entry(key)
            .or_insert(PendingBatch {
                shard_count: record.shard_count,
                parts: BTreeMap::new(),
                expires_at_ms: record.expires_at_ms,
                received_at: now,
            });
        if pending.shard_count != record.shard_count
            || pending.expires_at_ms != record.expires_at_ms
        {
            self.mailbox_wire.batches.remove(&key);
            return Err(AslError::InvalidMessage);
        }
        pending
            .parts
            .entry(record.shard_index)
            .or_insert_with(|| record.ciphertext.clone());
        if pending.parts.len() < usize::from(pending.shard_count) {
            return Ok(Vec::new());
        }
        let pending = self
            .mailbox_wire
            .batches
            .remove(&key)
            .ok_or(AslError::NotFound)?;
        let mut bytes = Vec::new();
        for index in 0..pending.shard_count {
            let part = pending.parts.get(&index).ok_or(AslError::InvalidMessage)?;
            bytes.extend_from_slice(part);
        }
        let packets = decode_batch(&bytes)?
            .into_iter()
            .map(|frame| {
                let WireFrame::GroupEnvelope(envelope) = decode_frame(&frame)? else {
                    return Err(AslError::InvalidMessage);
                };
                Ok(ReassembledGroupPacket {
                    packet: GroupPacket::from_envelope(envelope)?,
                })
            })
            .collect::<Result<Vec<_>, AslError>>()?;
        Ok(packets)
    }

    pub(super) fn deliver_mailbox_record(
        &mut self,
        record: &MailboxRecord,
        now_ms: u64,
    ) -> Result<(), AslError> {
        let Ok(packets) = self.handle_mailbox_record(record, now_ms) else {
            return Ok(());
        };
        for reassembled in packets {
            let group_id = reassembled.packet.group_id;
            let payload = encode_frame(&WireFrame::GroupEnvelope(
                reassembled.packet.into_envelope()?,
            ))?;
            let _ = self.handle_group_gossip(group_id, &payload, now_ms);
        }
        Ok(())
    }
}

fn send_mailbox_command(net: &super::NetRuntime, command: NetworkCommand) -> Result<(), AslError> {
    if net.try_send(&command.into_ipc()?)? {
        Ok(())
    } else {
        Err(AslError::SandboxUnavailable)
    }
}

fn refresh_known_senders(
    runtime: &mut MailboxWireRuntime,
    store: &Store,
    local_agent: AgentId,
) -> Result<(), AslError> {
    if runtime.initialized {
        return Ok(());
    }
    let mut senders = store.authorized_contacts()?;
    for contact in store.paired_contacts()? {
        if !senders.contains(&contact.agent_id) {
            senders.push(contact.agent_id);
        }
    }
    for (_, group_id) in store.list_mls_room_ids()? {
        for member in store.group_members(&group_id)? {
            if let Some(agent) = store.mls_peer_agent(&member.peer)?
                && agent != local_agent
                && !senders.contains(&agent)
            {
                senders.push(agent);
            }
        }
    }
    senders.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    runtime.known_senders = senders;
    runtime.initialized = true;
    Ok(())
}

fn publish_due(
    runtime: &mut MailboxWireRuntime,
    store: &Store,
    local_agent: AgentId,
    now_ms: u64,
    mut send: impl FnMut(NetworkCommand) -> Result<(), AslError>,
) -> Result<(), AslError> {
    let current_epoch = now_ms / MAILBOX_EPOCH_MS;
    let now = Instant::now();
    let mut recipients = Vec::new();
    for (_, group_id) in store.list_mls_room_ids()? {
        for member in store.group_members(&group_id)? {
            if let Some(agent) = store.mls_peer_agent(&member.peer)?
                && agent != local_agent
                && !recipients.contains(&agent)
            {
                recipients.push(agent);
            }
        }
    }
    recipients.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    'publish: for recipient_id in recipients {
        for lookback in 0..=MAILBOX_EPOCH_LOOKBACK {
            if runtime.publish_ops.len() >= MAX_PUBLISH_IN_FLIGHT {
                break 'publish;
            }
            let epoch = current_epoch.saturating_sub(lookback);
            let topic_id = mailbox_topic(recipient_id, local_agent, epoch);
            let envelopes = store.list_mailbox_envelopes(
                &topic_id,
                i64::try_from(now_ms).map_err(|_| AslError::InvalidMessage)?,
                64,
            )?;
            if envelopes.is_empty() {
                continue;
            }
            let mut packets = Vec::new();
            let mut size = MAX_BATCH_HEADER_BYTES;
            let mut expires_at_ms = u64::MAX;
            for envelope in &envelopes {
                let item_size = 4_usize.saturating_add(envelope.ciphertext.len());
                if size.saturating_add(item_size) > MAX_BATCH_BYTES {
                    break;
                }
                size += item_size;
                expires_at_ms = expires_at_ms.min(
                    u64::try_from(envelope.expires_at_ms).map_err(|_| AslError::InvalidMessage)?,
                );
                packets.push(envelope.ciphertext.clone());
            }
            if packets.is_empty() {
                continue;
            }
            let batch = encode_batch(&packets)?;
            let batch_hash = digest(b"ASL-MAILBOX-BATCH-v1\0", &batch);
            let key = PublishKey {
                recipient_id,
                sender_id: local_agent,
                epoch,
                batch_hash,
            };
            if runtime.published.get(&key).is_some_and(|published| {
                now.saturating_duration_since(*published) < PUBLISH_INTERVAL
            }) {
                continue;
            }
            let chunks = batch
                .chunks(MailboxRecord::MAX_CIPHERTEXT_BYTES)
                .collect::<Vec<_>>();
            if chunks.is_empty() || chunks.len() > usize::from(MAILBOX_SLOTS) {
                return Err(AslError::QuotaExceeded);
            }
            let shard_count = u16::try_from(chunks.len()).map_err(|_| AslError::InvalidMessage)?;
            for (index, chunk) in chunks.into_iter().enumerate() {
                if runtime.publish_ops.len() >= MAX_PUBLISH_IN_FLIGHT {
                    break 'publish;
                }
                let shard_id = digest(b"ASL-MAILBOX-SHARD-v1\0", chunk);
                let record = MailboxRecord {
                    recipient_id: recipient_id.0,
                    sender_id: local_agent.0,
                    topic_id,
                    mailbox_id: batch_hash,
                    shard_id,
                    epoch,
                    shard_index: u16::try_from(index).map_err(|_| AslError::InvalidMessage)?,
                    shard_count,
                    expires_at_ms,
                    ciphertext: chunk.to_vec(),
                };
                let operation_id = super::fresh_id()?;
                send(NetworkCommand::PublishMailboxRecord {
                    operation_id,
                    record,
                })?;
                runtime.publish_ops.insert(operation_id, key);
            }
        }
    }
    Ok(())
}

fn schedule_lookups(
    runtime: &mut MailboxWireRuntime,
    now: Instant,
    current_epoch: u64,
    local_agent: AgentId,
    mut send: impl FnMut(NetworkCommand) -> Result<(), AslError>,
) -> Result<(), AslError> {
    if runtime.queued_lookups.is_empty()
        && runtime.sender_cursor < runtime.known_senders.len()
        && runtime.lookups.len() < MAX_PENDING_LOOKUPS
    {
        let sender_id = runtime.known_senders[runtime.sender_cursor];
        runtime.sender_cursor += 1;
        for lookback in 0..=MAILBOX_EPOCH_LOOKBACK {
            let epoch = current_epoch.saturating_sub(lookback);
            for slot in 0..MAILBOX_SLOTS {
                runtime.queued_lookups.push_back(LookupIntent {
                    sender_id,
                    epoch,
                    slot,
                });
            }
        }
    }
    while runtime.lookups.len() < MAX_PENDING_LOOKUPS && !runtime.queued_lookups.is_empty() {
        let intent = runtime.queued_lookups.pop_front().unwrap();
        let key = asl_net::mailbox::mailbox_record_key(
            local_agent.0,
            intent.sender_id.0,
            intent.epoch,
            intent.slot,
        )?;
        let key_bytes: [u8; 32] = key
            .as_ref()
            .try_into()
            .map_err(|_| AslError::InvalidMessage)?;
        let operation_id = super::fresh_id()?;
        if let Err(error) = send(NetworkCommand::LookupDhtRecord {
            operation_id,
            key: key_bytes,
        }) {
            if matches!(
                error,
                AslError::SandboxUnavailable | AslError::QuotaExceeded
            ) {
                runtime.queued_lookups.push_front(intent);
                break;
            }
            return Err(error);
        }
        runtime.lookups.insert(operation_id, intent);
        runtime.lookup_started.insert(operation_id, now);
    }
    Ok(())
}

fn expire_lookup_state(runtime: &mut MailboxWireRuntime, now: Instant) {
    let expired = runtime
        .lookup_started
        .iter()
        .filter_map(|(operation_id, started)| {
            (now.saturating_duration_since(*started) >= LOOKUP_LIFETIME).then_some(*operation_id)
        })
        .collect::<Vec<_>>();
    for operation_id in expired {
        runtime.lookups.remove(&operation_id);
        runtime.lookup_started.remove(&operation_id);
    }
    runtime
        .batches
        .retain(|_, batch| now.saturating_duration_since(batch.received_at) < FETCH_INTERVAL);
    runtime.published.retain(|_, published_at| {
        now.saturating_duration_since(*published_at) < Duration::from_secs(24 * 60 * 60)
    });
    if runtime.seen_records.len() > 4096 {
        runtime.seen_records.clear();
    }
}

fn group_recipient_agents(
    store: &Store,
    room: Hash32,
    local_agent: AgentId,
) -> Result<Vec<AgentId>, AslError> {
    let snapshot = store.mls_room_snapshot(room)?.ok_or(AslError::NotFound)?;
    let mut agents = Vec::new();
    for member in store.group_members(&snapshot.local_id)? {
        if let Some(agent) = store.mls_peer_agent(&member.peer)?
            && agent != local_agent
            && !agents.contains(&agent)
        {
            agents.push(agent);
        }
    }
    Ok(agents)
}

fn mailbox_topic(recipient: AgentId, sender: AgentId, epoch: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MAILBOX_TOPIC_DOMAIN);
    hasher.update(recipient.as_bytes());
    hasher.update(sender.as_bytes());
    hasher.update(&epoch.to_be_bytes());
    *hasher.finalize().as_bytes()
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn padded_size(length: usize) -> Result<u32, AslError> {
    let rounded = length.checked_add(255).ok_or(AslError::InvalidMessage)? / 256 * 256;
    u32::try_from(rounded)
        .ok()
        .filter(|size| *size <= 1024 * 1024)
        .ok_or(AslError::QuotaExceeded)
}

fn encode_batch(packets: &[Vec<u8>]) -> Result<Vec<u8>, AslError> {
    if packets.is_empty() || packets.len() > u16::MAX as usize {
        return Err(AslError::InvalidMessage);
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(BATCH_MAGIC);
    bytes.push(BATCH_VERSION);
    bytes.extend_from_slice(
        &u16::try_from(packets.len())
            .map_err(|_| AslError::InvalidMessage)?
            .to_be_bytes(),
    );
    for packet in packets {
        bytes.extend_from_slice(
            &u32::try_from(packet.len())
                .map_err(|_| AslError::InvalidMessage)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(packet);
    }
    if bytes.len() > MAX_BATCH_BYTES {
        return Err(AslError::QuotaExceeded);
    }
    Ok(bytes)
}

fn decode_batch(bytes: &[u8]) -> Result<Vec<Vec<u8>>, AslError> {
    if bytes.len() < MAX_BATCH_HEADER_BYTES
        || bytes.get(..8) != Some(BATCH_MAGIC)
        || bytes[8] != BATCH_VERSION
    {
        return Err(AslError::InvalidMessage);
    }
    let count = u16::from_be_bytes(bytes[9..11].try_into().unwrap()) as usize;
    if count == 0 {
        return Err(AslError::InvalidMessage);
    }
    let mut offset = MAX_BATCH_HEADER_BYTES;
    let mut packets = Vec::with_capacity(count);
    for _ in 0..count {
        let length = bytes
            .get(offset..offset + 4)
            .and_then(|value| value.try_into().ok())
            .map(u32::from_be_bytes)
            .ok_or(AslError::InvalidMessage)? as usize;
        offset += 4;
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= bytes.len())
            .ok_or(AslError::InvalidMessage)?;
        if length == 0 {
            return Err(AslError::InvalidMessage);
        }
        packets.push(bytes[offset..end].to_vec());
        offset = end;
    }
    if offset != bytes.len() {
        return Err(AslError::InvalidMessage);
    }
    Ok(packets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mailbox_topic_is_stable_and_binds_route_and_epoch() {
        let base = mailbox_topic(AgentId([1; 32]), AgentId([2; 32]), 7);
        assert_eq!(base, mailbox_topic(AgentId([1; 32]), AgentId([2; 32]), 7));
        assert_ne!(base, mailbox_topic(AgentId([9; 32]), AgentId([2; 32]), 7));
        assert_ne!(base, mailbox_topic(AgentId([1; 32]), AgentId([9; 32]), 7));
        assert_ne!(base, mailbox_topic(AgentId([1; 32]), AgentId([2; 32]), 8));
    }

    #[test]
    fn batch_codec_round_trips_and_rejects_trailing_data() {
        let packets = vec![vec![1; 32], vec![2; 64]];
        let bytes = encode_batch(&packets).unwrap();
        assert_eq!(decode_batch(&bytes).unwrap(), packets);
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_batch(&trailing).is_err());
        assert!(decode_batch(b"arbitrary text").is_err());
    }
}
