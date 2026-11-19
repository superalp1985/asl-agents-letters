//! Bounded autonomous task state machine.

mod query;

pub use query::{
    INBOUND_DEDUP_WINDOW_MS, InboundQueryDecision, MAX_ACTIVE_TASKS, MAX_DHT_TERMS,
    MAX_INBOUND_DEDUP, MAX_QUERY_PEERS, OutgoingTask, QUERY_WINDOW_MS, QueryAction, QueryRouter,
    QueryScope, QueryStatus,
};
