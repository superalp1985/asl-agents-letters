use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
    protocol::{Query, WireFrame, decode_control, encode_control},
    task::TaskId,
};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, TransactionBehavior, params};

use crate::{Store, chain::agent_text, database_error};

const MAX_ROUNDS: i64 = 3;
const MAX_SEMANTIC_MESSAGES: i64 = 6;
const MAX_RETRIES: i64 = 3;
const CONVERSATION_WINDOW_MS: i64 = 10 * 60 * 1_000;
const RETRY_DELAYS_MS: [i64; 3] = [1_000, 10_000, 60_000];
const MAX_OUTBOX_BATCH: u32 = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskDirection {
    Incoming,
    Outgoing,
}

impl TaskDirection {
    fn as_str(self) -> &'static str {
        match self {
            Self::Incoming => "incoming",
            Self::Outgoing => "outgoing",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageDirection {
    Incoming,
    Outgoing,
}

impl MessageDirection {
    fn as_str(self) -> &'static str {
        match self {
            Self::Incoming => "in",
            Self::Outgoing => "out",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageKind {
    Query,
    Answer,
    Offer,
    Error,
    Ack,
}

impl MessageKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Answer => "answer",
            Self::Offer => "offer",
            Self::Error => "error",
            Self::Ack => "ack",
        }
    }

    fn is_semantic(self) -> bool {
        matches!(self, Self::Query | Self::Answer | Self::Offer)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageInsert {
    Inserted,
    Duplicate,
}

pub struct ConversationTaskSpec<'a> {
    pub task_id: TaskId,
    pub agent_id: AgentId,
    pub peer_id: &'a PeerId,
    pub direction: TaskDirection,
    pub query: Option<&'a Query>,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredOutboxMessage {
    pub task_id: TaskId,
    pub message_id: Id128,
    pub peer_id: PeerId,
    pub frame: WireFrame,
    pub attempts: u8,
    pub next_attempt_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboxFailure {
    Rescheduled { attempts: u8, next_attempt_ms: i64 },
    Exhausted,
    Expired,
}

impl Store {
    pub fn create_conversation_task(
        &mut self,
        spec: ConversationTaskSpec<'_>,
    ) -> Result<(), AslError> {
        if spec.created_at_ms < 0
            || spec.expires_at_ms < spec.created_at_ms
            || spec.expires_at_ms - spec.created_at_ms > CONVERSATION_WINDOW_MS
        {
            return Err(AslError::InvalidMessage);
        }
        if let Some(query) = spec.query
            && query.root_task_id != spec.task_id.0
        {
            return Err(AslError::InvalidMessage);
        }
        let query_cbor = spec
            .query
            .map(|query| encode_control(&WireFrame::Query(query.clone())))
            .transpose()?;
        let tx = immediate(&mut self.connection)?;
        tx.execute(
            "INSERT INTO tasks(
                task_id,direction,agent_id,peer_id,semantic_query_cbor,audience_json,
                state,rounds_used,requests_used,created_at_ms,expires_at_ms
             ) VALUES (?1,?2,?3,?4,?5,'{\"kind\":\"peer\"}','searching',0,0,?6,?7)",
            params![
                id_text(spec.task_id.0),
                spec.direction.as_str(),
                agent_text(spec.agent_id),
                peer_text(spec.peer_id),
                query_cbor,
                spec.created_at_ms,
                spec.expires_at_ms
            ],
        )
        .map_err(database_error)?;
        tx.commit().map_err(database_error)
    }

    pub fn store_incoming_message(
        &mut self,
        task_id: &TaskId,
        peer_id: &PeerId,
        frame: &WireFrame,
        now_ms: i64,
        expires_at_ms: i64,
    ) -> Result<MessageInsert, AslError> {
        self.store_message(MessageWrite {
            task_id,
            peer_id,
            direction: MessageDirection::Incoming,
            frame,
            now_ms,
            expires_at_ms,
            enqueue: false,
        })
    }

    pub fn enqueue_outgoing_message(
        &mut self,
        task_id: &TaskId,
        peer_id: &PeerId,
        frame: &WireFrame,
        now_ms: i64,
        expires_at_ms: i64,
    ) -> Result<MessageInsert, AslError> {
        self.store_message(MessageWrite {
            task_id,
            peer_id,
            direction: MessageDirection::Outgoing,
            frame,
            now_ms,
            expires_at_ms,
            enqueue: true,
        })
    }

    pub fn claim_processed_request(
        &mut self,
        agent_id: AgentId,
        request_id: Id128,
        now_ms: i64,
        expires_at_ms: i64,
    ) -> Result<bool, AslError> {
        if now_ms < 0 || expires_at_ms <= now_ms || expires_at_ms - now_ms > CONVERSATION_WINDOW_MS
        {
            return Err(AslError::InvalidMessage);
        }
        let tx = immediate(&mut self.connection)?;
        tx.execute(
            "DELETE FROM processed_requests WHERE expires_at_ms <= ?1",
            [now_ms],
        )
        .map_err(database_error)?;
        let inserted = tx
            .execute(
                "INSERT OR IGNORE INTO processed_requests(agent_id,request_id,expires_at_ms)
                 VALUES (?1,?2,?3)",
                params![agent_text(agent_id), id_text(request_id), expires_at_ms],
            )
            .map_err(database_error)?;
        tx.commit().map_err(database_error)?;
        Ok(inserted == 1)
    }

    /// Atomically deduplicates an incoming query and charges its durable
    /// AgentId/root-task conversation budget.
    pub fn claim_direct_inbound_query(
        &mut self,
        agent_id: AgentId,
        root_task_id: Id128,
        request_id: Id128,
        now_ms: i64,
        expires_at_ms: i64,
    ) -> Result<bool, AslError> {
        if now_ms < 0 || expires_at_ms <= now_ms || expires_at_ms - now_ms > CONVERSATION_WINDOW_MS
        {
            return Err(AslError::InvalidMessage);
        }
        let tx = immediate(&mut self.connection)?;
        tx.execute(
            "DELETE FROM processed_requests WHERE expires_at_ms<=?1",
            [now_ms],
        )
        .map_err(database_error)?;
        tx.execute(
            "DELETE FROM direct_inbound_conversations WHERE expires_at_ms<=?1",
            [now_ms],
        )
        .map_err(database_error)?;
        let inserted = tx
            .execute(
                "INSERT OR IGNORE INTO processed_requests(agent_id,request_id,expires_at_ms)
             VALUES (?1,?2,?3)",
                params![agent_text(agent_id), id_text(request_id), expires_at_ms],
            )
            .map_err(database_error)?;
        if inserted == 0 {
            tx.commit().map_err(database_error)?;
            return Ok(false);
        }
        let charged = tx
            .execute(
                "INSERT INTO direct_inbound_conversations
                (agent_id,root_task_id,rounds_used,messages_used,expires_at_ms)
             VALUES (?1,?2,1,1,?3)
             ON CONFLICT(agent_id,root_task_id) DO UPDATE SET
                rounds_used=rounds_used+1,messages_used=messages_used+1
             WHERE expires_at_ms>?4 AND rounds_used<3 AND messages_used<6",
                params![
                    agent_text(agent_id),
                    id_text(root_task_id),
                    now_ms.saturating_add(CONVERSATION_WINDOW_MS),
                    now_ms
                ],
            )
            .map_err(database_error)?;
        if charged != 1 {
            return Err(AslError::QuotaExceeded);
        }
        tx.commit().map_err(database_error)?;
        Ok(true)
    }

    /// Group messages share the same bounded semantic budget table, but the
    /// conversation key includes the wire group ID so the same message ID in
    /// another room cannot consume or suppress this room's request.
    pub fn claim_group_inbound_query(
        &mut self,
        group_id: Hash32,
        sender: AgentId,
        root_task_id: Id128,
        request_id: Id128,
        now_ms: i64,
        expires_at_ms: i64,
    ) -> Result<bool, AslError> {
        self.claim_direct_inbound_query(
            sender,
            scoped_group_id(b"root", group_id, root_task_id),
            scoped_group_id(b"request", group_id, request_id),
            now_ms,
            expires_at_ms,
        )
    }

    pub fn due_outbox(
        &self,
        now_ms: i64,
        limit: u32,
    ) -> Result<Vec<StoredOutboxMessage>, AslError> {
        if now_ms < 0 {
            return Err(AslError::InvalidMessage);
        }
        let limit = limit.min(MAX_OUTBOX_BATCH);
        let mut statement = self
            .connection
            .prepare(
                "SELECT o.message_id,m.task_id,m.peer_id,m.body_cbor,o.attempts,
                        o.next_attempt_ms,o.expires_at_ms
                 FROM outbox o
                 JOIN messages m ON m.message_id=o.message_id
                 WHERE o.next_attempt_ms <= ?1 AND o.expires_at_ms > ?1
                 ORDER BY o.next_attempt_ms,o.message_id
                 LIMIT ?2",
            )
            .map_err(database_error)?;
        let rows = statement
            .query_map(params![now_ms, i64::from(limit)], read_outbox)
            .map_err(database_error)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(database_error)?
            .into_iter()
            .map(decode_outbox)
            .collect()
    }

    pub fn mark_outbox_delivered(&self, message_id: Id128) -> Result<(), AslError> {
        let changed = self
            .connection
            .execute(
                "DELETE FROM outbox WHERE message_id=?1",
                [id_text(message_id)],
            )
            .map_err(database_error)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(AslError::NotFound)
        }
    }

    pub fn mark_outbox_failed(
        &mut self,
        message_id: Id128,
        now_ms: i64,
    ) -> Result<OutboxFailure, AslError> {
        if now_ms < 0 {
            return Err(AslError::InvalidMessage);
        }
        let tx = immediate(&mut self.connection)?;
        let current: Option<(i64, i64)> = tx
            .query_row(
                "SELECT attempts,expires_at_ms FROM outbox WHERE message_id=?1",
                [id_text(message_id)],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(database_error)?;
        let Some((attempts, expires_at_ms)) = current else {
            return Err(AslError::NotFound);
        };
        if now_ms >= expires_at_ms {
            tx.execute(
                "DELETE FROM outbox WHERE message_id=?1",
                [id_text(message_id)],
            )
            .map_err(database_error)?;
            tx.commit().map_err(database_error)?;
            return Ok(OutboxFailure::Expired);
        }
        if attempts >= MAX_RETRIES {
            tx.execute(
                "DELETE FROM outbox WHERE message_id=?1",
                [id_text(message_id)],
            )
            .map_err(database_error)?;
            tx.commit().map_err(database_error)?;
            return Ok(OutboxFailure::Exhausted);
        }
        let delay =
            RETRY_DELAYS_MS[usize::try_from(attempts).map_err(|_| AslError::InvalidDatabase)?];
        let next_attempt_ms = now_ms.saturating_add(delay).min(expires_at_ms);
        let next_attempts = attempts + 1;
        tx.execute(
            "UPDATE outbox SET attempts=?2,next_attempt_ms=?3
             WHERE message_id=?1",
            params![id_text(message_id), next_attempts, next_attempt_ms],
        )
        .map_err(database_error)?;
        tx.commit().map_err(database_error)?;
        Ok(OutboxFailure::Rescheduled {
            attempts: u8::try_from(next_attempts).map_err(|_| AslError::InvalidDatabase)?,
            next_attempt_ms,
        })
    }

    pub fn purge_expired_conversation_state(&mut self, now_ms: i64) -> Result<(), AslError> {
        if now_ms < 0 {
            return Err(AslError::InvalidMessage);
        }
        let tx = immediate(&mut self.connection)?;
        tx.execute("DELETE FROM outbox WHERE expires_at_ms <= ?1", [now_ms])
            .map_err(database_error)?;
        tx.execute(
            "DELETE FROM processed_requests WHERE expires_at_ms <= ?1",
            [now_ms],
        )
        .map_err(database_error)?;
        tx.commit().map_err(database_error)
    }

    fn store_message(&mut self, write: MessageWrite<'_>) -> Result<MessageInsert, AslError> {
        let MessageWrite {
            task_id,
            peer_id,
            direction,
            frame,
            now_ms,
            expires_at_ms,
            enqueue,
        } = write;
        if now_ms < 0 || expires_at_ms <= now_ms || expires_at_ms - now_ms > CONVERSATION_WINDOW_MS
        {
            return Err(AslError::InvalidMessage);
        }
        let info = frame_info(frame)?;
        let body = encode_control(frame)?;
        let tx = immediate(&mut self.connection)?;
        let task_row: Option<(i64, i64, i64, String)> = tx
            .query_row(
                "SELECT expires_at_ms,rounds_used,requests_used,peer_id
                 FROM tasks WHERE task_id=?1",
                [id_text(task_id.0)],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(database_error)?;
        let Some((task_expires_at_ms, rounds_used, semantic_messages, task_peer)) = task_row else {
            return Err(AslError::NotFound);
        };
        if task_peer != peer_text(peer_id) {
            return Err(AslError::InvalidMessage);
        }
        if now_ms >= task_expires_at_ms || expires_at_ms > task_expires_at_ms {
            return Err(AslError::ExpiredMessage);
        }

        let existing: Option<(String, String, String, String, Vec<u8>)> = tx
            .query_row(
                "SELECT task_id,peer_id,direction,kind,body_cbor
                 FROM messages WHERE message_id=?1",
                [id_text(info.message_id)],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(database_error)?;
        if let Some((
            existing_task,
            existing_peer,
            existing_direction,
            existing_kind,
            existing_body,
        )) = existing
        {
            if existing_task == id_text(task_id.0)
                && existing_peer == peer_text(peer_id)
                && existing_direction == direction.as_str()
                && existing_kind == info.kind.as_str()
                && existing_body == body
            {
                return Ok(MessageInsert::Duplicate);
            }
            return Err(AslError::InvalidMessage);
        }

        if info.kind.is_semantic() {
            if semantic_messages >= MAX_SEMANTIC_MESSAGES {
                return Err(AslError::QuotaExceeded);
            }
            if info.kind == MessageKind::Query && rounds_used >= MAX_ROUNDS {
                return Err(AslError::QuotaExceeded);
            }
        }
        tx.execute(
            "INSERT INTO messages(
                message_id,task_id,peer_id,direction,kind,body_cbor,created_at_ms,expires_at_ms
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                id_text(info.message_id),
                id_text(task_id.0),
                peer_text(peer_id),
                direction.as_str(),
                info.kind.as_str(),
                body,
                now_ms,
                expires_at_ms
            ],
        )
        .map_err(database_error)?;

        if info.kind.is_semantic() {
            tx.execute(
                "UPDATE tasks
                 SET requests_used=requests_used+1,
                     rounds_used=rounds_used+?2
                 WHERE task_id=?1",
                params![
                    id_text(task_id.0),
                    i64::from(info.kind == MessageKind::Query)
                ],
            )
            .map_err(database_error)?;
        }
        if enqueue {
            tx.execute(
                "INSERT INTO outbox(message_id,attempts,next_attempt_ms,expires_at_ms)
                 VALUES (?1,0,?2,?3)",
                params![id_text(info.message_id), now_ms, expires_at_ms],
            )
            .map_err(database_error)?;
        }
        tx.commit().map_err(database_error)?;
        Ok(MessageInsert::Inserted)
    }
}

pub(crate) fn scoped_group_id(domain: &[u8], group_id: Hash32, id: Id128) -> Id128 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ASL-group-inbound-v1\0");
    hasher.update(domain);
    hasher.update(b"\0");
    hasher.update(group_id.as_bytes());
    hasher.update(id.as_bytes());
    let digest = hasher.finalize();
    let mut scoped = [0_u8; 16];
    scoped.copy_from_slice(&digest.as_bytes()[..16]);
    Id128(scoped)
}

struct MessageWrite<'a> {
    task_id: &'a TaskId,
    peer_id: &'a PeerId,
    direction: MessageDirection,
    frame: &'a WireFrame,
    now_ms: i64,
    expires_at_ms: i64,
    enqueue: bool,
}

struct FrameInfo {
    message_id: Id128,
    kind: MessageKind,
}

fn frame_info(frame: &WireFrame) -> Result<FrameInfo, AslError> {
    let (message_id, kind) = match frame {
        WireFrame::Query(value) => (value.message_id, MessageKind::Query),
        WireFrame::Answer(value) => (value.message_id, MessageKind::Answer),
        WireFrame::Offer(value) => (value.message_id, MessageKind::Offer),
        WireFrame::Error(value) => (value.message_id, MessageKind::Error),
        WireFrame::Ack(value) => (value.message_id, MessageKind::Ack),
        WireFrame::FetchRequest(_)
        | WireFrame::FetchGrant(_)
        | WireFrame::FetchPending(_)
        | WireFrame::Hello(_)
        | WireFrame::Profile(_)
        | WireFrame::IdentityProofRequest(_)
        | WireFrame::IdentityProof(_)
        | WireFrame::PairingInvite(_)
        | WireFrame::PairingExchange(_)
        | WireFrame::GroupEnvelope(_) => return Err(AslError::InvalidMessage),
    };
    Ok(FrameInfo { message_id, kind })
}

struct RawOutbox {
    task_id: String,
    message_id: String,
    peer_id: String,
    body: Vec<u8>,
    attempts: i64,
    next_attempt_ms: i64,
    expires_at_ms: i64,
}

fn read_outbox(row: &Row<'_>) -> rusqlite::Result<RawOutbox> {
    Ok(RawOutbox {
        message_id: row.get(0)?,
        task_id: row.get(1)?,
        peer_id: row.get(2)?,
        body: row.get(3)?,
        attempts: row.get(4)?,
        next_attempt_ms: row.get(5)?,
        expires_at_ms: row.get(6)?,
    })
}

fn decode_outbox(raw: RawOutbox) -> Result<StoredOutboxMessage, AslError> {
    if !(0..=MAX_RETRIES).contains(&raw.attempts) {
        return Err(AslError::InvalidDatabase);
    }
    let message_id = parse_id(&raw.message_id)?;
    let frame = decode_control(&raw.body)?;
    if frame_info(&frame)?.message_id != message_id {
        return Err(AslError::InvalidDatabase);
    }
    Ok(StoredOutboxMessage {
        task_id: TaskId(parse_id(&raw.task_id)?),
        message_id,
        peer_id: parse_peer(&raw.peer_id)?,
        frame,
        attempts: u8::try_from(raw.attempts).map_err(|_| AslError::InvalidDatabase)?,
        next_attempt_ms: raw.next_attempt_ms,
        expires_at_ms: raw.expires_at_ms,
    })
}

fn id_text(id: Id128) -> String {
    hex::encode(id.0)
}

fn parse_id(value: &str) -> Result<Id128, AslError> {
    let mut bytes = [0_u8; 16];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| AslError::InvalidDatabase)?;
    Ok(Id128(bytes))
}

fn peer_text(peer: &PeerId) -> String {
    bs58::encode(peer.as_bytes()).into_string()
}

fn parse_peer(value: &str) -> Result<PeerId, AslError> {
    let bytes = bs58::decode(value)
        .into_vec()
        .map_err(|_| AslError::InvalidDatabase)?;
    PeerId::from_bytes(bytes).map_err(|_| AslError::InvalidDatabase)
}

fn immediate(conn: &mut Connection) -> Result<Transaction<'_>, AslError> {
    conn.transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(database_error)
}

#[cfg(test)]
mod group_scope_tests {
    use super::*;
    use asl_types::ids::AgentId;

    #[test]
    fn group_query_replay_scope_includes_the_wire_group_id() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = crate::open_store(&temp.path().join("asl.sqlite3")).unwrap();
        let agent = AgentId([1; 32]);
        let root = Id128([2; 16]);
        let message = Id128([3; 16]);
        let first_group = Hash32([4; 32]);
        let second_group = Hash32([5; 32]);

        store
            .connection
            .execute(
                "INSERT INTO agents(agent_id) VALUES (?1)",
                [agent_text(agent)],
            )
            .unwrap();

        assert!(
            store
                .claim_group_inbound_query(first_group, agent, root, message, 100, 1_000)
                .unwrap()
        );
        assert!(
            !store
                .claim_group_inbound_query(first_group, agent, root, message, 101, 1_000)
                .unwrap()
        );
        assert!(
            store
                .claim_group_inbound_query(second_group, agent, root, message, 101, 1_000)
                .unwrap()
        );
    }
}
