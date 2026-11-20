use std::collections::VecDeque;

use asl_types::{ids::AgentId, record::RecordPayload};

use crate::profile::VerifiedRecord;

const MAX_DIRECTORIES: usize = 128;

/// A bounded source of signed bytes, not an authorization cache. Keeping the
/// verified input after disconnect avoids requiring simultaneous connections.
#[derive(Default)]
pub(in crate::profile::admission) struct GroupDirectoryCache(VecDeque<(AgentId, Vec<u8>)>);

impl GroupDirectoryCache {
    pub(in crate::profile::admission) fn observe(&mut self, record: &VerifiedRecord) {
        let RecordPayload::DeviceDirectory(directory) = &record.signed().record.payload else {
            return;
        };
        let agent = directory.agent_id;
        self.0.retain(|(owner, _)| *owner != agent);
        if self.0.len() == MAX_DIRECTORIES {
            self.0.pop_front();
        }
        self.0.push_back((agent, record.bytes().to_vec()));
    }

    pub(super) fn get(&self, agent: AgentId) -> Option<&[u8]> {
        self.0
            .iter()
            .find(|(owner, _)| *owner == agent)
            .map(|(_, bytes)| bytes.as_slice())
    }
}
