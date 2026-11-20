//! Bounded autonomous task state machine.

mod conversation;
pub mod decision;
pub mod gateway;
pub mod knowledge;
mod query;
pub mod reputation;
pub mod runner;

pub use conversation::{
    CONVERSATION_WINDOW_MS, Conversation, ConversationMessageKind, InboundDecision,
    MAX_CONVERSATION_ROUNDS, MAX_OUTBOX_RETRIES, MAX_SEMANTIC_MESSAGES, PendingDelivery,
    RETRY_DELAYS_MS,
};
pub use query::{
    INBOUND_DEDUP_WINDOW_MS, InboundQueryDecision, MAX_ACTIVE_TASKS, MAX_DHT_TERMS,
    MAX_INBOUND_DEDUP, MAX_QUERY_PEERS, OutgoingTask, QUERY_WINDOW_MS, QueryAction, QueryRouter,
    QueryScope, QueryStatus,
};
