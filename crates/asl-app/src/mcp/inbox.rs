use std::collections::VecDeque;

use serde_json::{Value, json};

use super::contract::ServerFrame;

pub(super) const MAX_EVENTS: usize = 32;
// Leave room for JSON-RPC and escaping the resource's JSON text as a string.
const MAX_BYTES: usize = 256 * 1024;

#[derive(Default)]
pub(super) struct Inbox {
    events: VecDeque<(u64, usize, Value)>,
    bytes: usize,
    sequence: u64,
    dropped: u64,
}

impl Inbox {
    pub(super) fn push(&mut self, event: Value) {
        let Ok(bytes) = serde_json::to_vec(&event) else {
            return self.lose(1);
        };
        if bytes.len() > MAX_BYTES {
            return self.lose(1);
        }
        while self.events.len() >= MAX_EVENTS || self.bytes + bytes.len() > MAX_BYTES {
            let (_, bytes, _) = self.events.pop_front().expect("non-empty over budget");
            self.bytes -= bytes;
            self.dropped = self.dropped.saturating_add(1);
        }
        self.sequence = self.sequence.saturating_add(1);
        self.bytes += bytes.len();
        self.events.push_back((self.sequence, bytes.len(), event));
    }

    pub(super) fn lose(&mut self, count: u64) {
        self.sequence = self.sequence.saturating_add(count);
        self.dropped = self.dropped.saturating_add(count);
    }

    pub(super) fn has_updates(&self) -> bool {
        self.sequence != 0
    }

    pub(super) fn next(&mut self) -> Option<ServerFrame> {
        if self.dropped != 0 {
            return Some(ServerFrame::AgentEventLoss {
                dropped: std::mem::take(&mut self.dropped),
            });
        }
        let (_, bytes, event) = self.events.pop_front()?;
        self.bytes -= bytes;
        Some(ServerFrame::AgentEvent { event })
    }

    pub(super) fn snapshot(&self) -> Value {
        let events = self
            .events
            .iter()
            .map(|(sequence, _, event)| json!({ "sequence": sequence, "event": event }))
            .collect::<Vec<_>>();
        json!({ "events": events, "dropped": self.dropped, "sequence": self.sequence })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_a_maximum_control_frame_notification_for_the_agent() {
        let mut inbox = Inbox::default();
        inbox.push(json!({
            "kind": "context_expression",
            "details": {"control_cbor_hex": "ab".repeat(65_536)}
        }));
        assert_eq!(inbox.snapshot()["events"].as_array().unwrap().len(), 1);
        assert_eq!(inbox.snapshot()["dropped"], 0);
    }
}
