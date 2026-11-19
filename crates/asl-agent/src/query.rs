use std::collections::{HashMap, HashSet, VecDeque};

use asl_types::{
    error::AslError,
    ids::{Id128, PeerId},
    protocol::{ConceptRef, Constraint, Intent, Query, ResultShape},
    task::TaskId,
};
use rand::{TryRng, rngs::SysRng};

pub const MAX_DHT_TERMS: usize = 3;
pub const MAX_QUERY_PEERS: usize = 16;
pub const QUERY_WINDOW_MS: u64 = 10_000;
pub const INBOUND_DEDUP_WINDOW_MS: u64 = 10 * 60 * 1_000;
pub const MAX_INBOUND_DEDUP: usize = 20_000;
pub const MAX_ACTIVE_TASKS: usize = 256;
const MAX_QUERY_BUDGET: u8 = 64;
const MAX_QUERY_TOPICS: usize = 64;
const MAX_QUERY_CONSTRAINTS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryScope {
    ContactsOnly,
    Public,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutgoingTask {
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub intent_id: Intent,
    pub topics: Vec<ConceptRef>,
    pub constraints: Vec<Constraint>,
    pub result_shape: ResultShape,
    pub budget: u8,
    pub scope: QueryScope,
}

impl OutgoingTask {
    pub fn new(
        created_at_ms: u64,
        intent_id: Intent,
        topics: Vec<ConceptRef>,
        constraints: Vec<Constraint>,
        result_shape: ResultShape,
        budget: u8,
        scope: QueryScope,
    ) -> Self {
        Self {
            created_at_ms,
            expires_at_ms: created_at_ms.saturating_add(QUERY_WINDOW_MS),
            intent_id,
            topics,
            constraints,
            result_shape,
            budget,
            scope,
        }
    }

    pub fn with_expiry(mut self, expires_at_ms: u64) -> Self {
        self.expires_at_ms = expires_at_ms;
        self
    }

    fn validate(&self) -> Result<(), AslError> {
        if self.created_at_ms > i64::MAX as u64
            || self.expires_at_ms > i64::MAX as u64
            || self.expires_at_ms < self.created_at_ms
            || self.expires_at_ms - self.created_at_ms > QUERY_WINDOW_MS
            || self.topics.len() > MAX_QUERY_TOPICS
            || self.constraints.len() > MAX_QUERY_CONSTRAINTS
            || self.budget > MAX_QUERY_BUDGET
        {
            return Err(AslError::InvalidMessage);
        }
        if self
            .topics
            .iter()
            .enumerate()
            .any(|(index, topic)| !topic.is_topic() || self.topics[..index].contains(topic))
        {
            return Err(AslError::InvalidMessage);
        }
        Ok(())
    }

    fn query(&self, root_task_id: Id128, message_id: Id128) -> Query {
        Query {
            message_id,
            root_task_id,
            created_at_ms: self.created_at_ms,
            expires_at_ms: self.expires_at_ms,
            intent_id: self.intent_id,
            topics: self.topics.clone(),
            constraints: self.constraints.clone(),
            result_shape: self.result_shape,
            budget: self.budget,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QueryAction {
    Contact {
        task_id: TaskId,
        peer_id: PeerId,
        query: Query,
    },
    DhtLookup {
        task_id: TaskId,
        concept: ConceptRef,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryStatus {
    Active,
    Complete,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InboundQueryDecision {
    ExecuteLocally { query: Query },
    Duplicate,
    Expired,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct InboundKey {
    peer_id: PeerId,
    message_id: Id128,
}

struct ActiveTask {
    query: Query,
    scope: QueryScope,
    status: QueryStatus,
    actions: VecDeque<QueryAction>,
    pending_contacts: HashSet<PeerId>,
    pending_peers: HashSet<PeerId>,
    direct_peers: HashSet<PeerId>,
    dht_terms: Vec<ConceptRef>,
    pending_dht_terms: Vec<ConceptRef>,
    dht_started: bool,
}

pub struct QueryRouter {
    contacts: Vec<PeerId>,
    tasks: HashMap<TaskId, ActiveTask>,
    inbound_seen: HashMap<InboundKey, u64>,
    inbound_order: VecDeque<(InboundKey, u64)>,
}

impl Default for QueryRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryRouter {
    pub fn new() -> Self {
        Self {
            contacts: Vec::new(),
            tasks: HashMap::new(),
            inbound_seen: HashMap::new(),
            inbound_order: VecDeque::new(),
        }
    }

    pub fn with_contacts(contacts: impl IntoIterator<Item = PeerId>) -> Self {
        let mut router = Self::new();
        router.set_contacts(contacts);
        router
    }

    pub fn set_contacts(&mut self, contacts: impl IntoIterator<Item = PeerId>) {
        self.contacts.clear();
        let mut seen = HashSet::new();
        for peer_id in contacts {
            if seen.insert(peer_id.clone()) {
                self.contacts.push(peer_id);
            }
        }
    }

    pub fn contacts(&self) -> &[PeerId] {
        &self.contacts
    }

    pub fn start_query(&mut self, task: OutgoingTask) -> Result<TaskId, AslError> {
        task.validate()?;
        if self.tasks.len() >= MAX_ACTIVE_TASKS {
            return Err(AslError::QuotaExceeded);
        }

        let root_task_id = fresh_task_id(&self.tasks)?;
        let task_id = TaskId(root_task_id);
        let mut query = task.query(root_task_id, fresh_id()?);
        let mut actions = VecDeque::new();
        let mut pending_contacts = HashSet::new();
        let pending_peers = HashSet::new();
        let mut direct_peers = HashSet::new();

        for peer_id in self.contacts.iter().take(MAX_QUERY_PEERS) {
            let peer_id = peer_id.clone();
            if !direct_peers.insert(peer_id.clone()) {
                continue;
            }
            pending_contacts.insert(peer_id.clone());
            query.message_id = fresh_id()?;
            actions.push_back(QueryAction::Contact {
                task_id: task_id.clone(),
                peer_id,
                query: query.clone(),
            });
        }

        let dht_terms = task.topics.iter().copied().take(MAX_DHT_TERMS).collect();
        let dht_started = pending_contacts.is_empty();
        let mut active = ActiveTask {
            query,
            scope: task.scope,
            status: QueryStatus::Active,
            actions,
            pending_contacts,
            pending_peers,
            direct_peers,
            dht_terms,
            pending_dht_terms: Vec::new(),
            dht_started: false,
        };
        if dht_started {
            activate_dht(&mut active, &task_id);
        }
        self.tasks.insert(task_id.clone(), active);
        Ok(task_id)
    }

    pub fn next_actions(&mut self, task_id: &TaskId, now_ms: u64) -> Vec<QueryAction> {
        let Some(task) = self.tasks.get_mut(task_id) else {
            return Vec::new();
        };
        if task.status == QueryStatus::Active && now_ms >= task.query.expires_at_ms {
            task.status = QueryStatus::Expired;
            task.actions.clear();
            task.pending_contacts.clear();
            task.pending_peers.clear();
            task.pending_dht_terms.clear();
        }
        if task.status != QueryStatus::Active {
            return Vec::new();
        }
        let actions = task.actions.drain(..).collect();
        maybe_complete(task);
        actions
    }

    pub fn drain_actions(&mut self, task_id: &TaskId, now_ms: u64) -> Vec<QueryAction> {
        self.next_actions(task_id, now_ms)
    }

    pub fn complete_peer(
        &mut self,
        task_id: &TaskId,
        peer_id: &PeerId,
        now_ms: u64,
    ) -> Result<(), AslError> {
        let task = self.tasks.get_mut(task_id).ok_or(AslError::NotFound)?;
        expire_if_needed(task, now_ms);
        if task.status != QueryStatus::Active {
            return Err(AslError::ExpiredMessage);
        }
        if !task.pending_contacts.remove(peer_id) && !task.pending_peers.remove(peer_id) {
            return Err(AslError::NotFound);
        }
        maybe_activate_dht(task, task_id);
        maybe_complete(task);
        Ok(())
    }

    pub fn record_dht_result(
        &mut self,
        task_id: &TaskId,
        concept: ConceptRef,
        peers: impl IntoIterator<Item = PeerId>,
        now_ms: u64,
    ) -> Result<(), AslError> {
        let task = self.tasks.get_mut(task_id).ok_or(AslError::NotFound)?;
        expire_if_needed(task, now_ms);
        if task.status != QueryStatus::Active {
            return Err(AslError::ExpiredMessage);
        }
        let Some(index) = task
            .pending_dht_terms
            .iter()
            .position(|pending| *pending == concept)
        else {
            return Err(AslError::NotFound);
        };
        task.pending_dht_terms.remove(index);

        for peer_id in peers {
            if task.direct_peers.len() >= MAX_QUERY_PEERS {
                break;
            }
            if task.direct_peers.insert(peer_id.clone()) {
                task.pending_peers.insert(peer_id.clone());
                let mut query = task.query.clone();
                query.message_id = fresh_id()?;
                task.actions.push_back(QueryAction::Contact {
                    task_id: task_id.clone(),
                    peer_id,
                    query,
                });
            }
        }
        maybe_complete(task);
        Ok(())
    }

    pub fn status(&self, task_id: &TaskId) -> Option<QueryStatus> {
        self.tasks.get(task_id).map(|task| task.status)
    }

    pub fn accept_incoming(
        &mut self,
        peer_id: PeerId,
        query: Query,
        now_ms: u64,
    ) -> Result<InboundQueryDecision, AslError> {
        if query.expires_at_ms <= now_ms {
            return Ok(InboundQueryDecision::Expired);
        }
        if query.created_at_ms > query.expires_at_ms
            || query.expires_at_ms - query.created_at_ms > QUERY_WINDOW_MS
            || query.created_at_ms > i64::MAX as u64
            || query.expires_at_ms > i64::MAX as u64
            || query.topics.len() > MAX_QUERY_TOPICS
            || query.constraints.len() > MAX_QUERY_CONSTRAINTS
            || query.budget > MAX_QUERY_BUDGET
            || query
                .topics
                .iter()
                .enumerate()
                .any(|(index, topic)| !topic.is_topic() || query.topics[..index].contains(topic))
        {
            return Err(AslError::InvalidMessage);
        }

        self.purge_inbound(now_ms);
        let key = InboundKey {
            peer_id,
            message_id: query.message_id,
        };
        if self.inbound_seen.contains_key(&key) {
            return Ok(InboundQueryDecision::Duplicate);
        }
        if self.inbound_seen.len() >= MAX_INBOUND_DEDUP {
            return Err(AslError::QuotaExceeded);
        }
        let retained_until = now_ms.saturating_add(INBOUND_DEDUP_WINDOW_MS);
        self.inbound_seen.insert(key.clone(), retained_until);
        self.inbound_order.push_back((key, retained_until));
        Ok(InboundQueryDecision::ExecuteLocally { query })
    }

    fn purge_inbound(&mut self, now_ms: u64) {
        while let Some((_, retained_until)) = self.inbound_order.front() {
            if *retained_until > now_ms {
                break;
            }
            let (key, retained_until) = self.inbound_order.pop_front().expect("front exists");
            if self.inbound_seen.get(&key) == Some(&retained_until) {
                self.inbound_seen.remove(&key);
            }
        }
    }
}

fn fresh_id() -> Result<Id128, AslError> {
    let mut id = [0; 16];
    for _ in 0..8 {
        SysRng
            .try_fill_bytes(&mut id)
            .map_err(|_| AslError::InvalidIdentity)?;
        if id != [0; 16] {
            return Ok(Id128(id));
        }
    }
    Err(AslError::QuotaExceeded)
}

fn fresh_task_id<T>(existing: &HashMap<TaskId, T>) -> Result<Id128, AslError> {
    for _ in 0..8 {
        let id = fresh_id()?;
        if !existing.contains_key(&TaskId(id)) {
            return Ok(id);
        }
    }
    Err(AslError::QuotaExceeded)
}

fn activate_dht(task: &mut ActiveTask, task_id: &TaskId) {
    if task.scope != QueryScope::Public
        || task.dht_started
        || task.direct_peers.len() >= MAX_QUERY_PEERS
    {
        task.dht_started = true;
        maybe_complete(task);
        return;
    }
    task.dht_started = true;
    for concept in task.dht_terms.iter().copied() {
        task.pending_dht_terms.push(concept);
        task.actions.push_back(QueryAction::DhtLookup {
            task_id: task_id.clone(),
            concept,
        });
    }
    maybe_complete(task);
}

fn maybe_activate_dht(task: &mut ActiveTask, task_id: &TaskId) {
    if task.pending_contacts.is_empty() && !task.dht_started {
        activate_dht(task, task_id);
    }
}

fn maybe_complete(task: &mut ActiveTask) {
    if task.pending_contacts.is_empty()
        && task.pending_peers.is_empty()
        && task.pending_dht_terms.is_empty()
        && task.actions.is_empty()
        && task.dht_started
    {
        task.status = QueryStatus::Complete;
    }
}

fn expire_if_needed(task: &mut ActiveTask, now_ms: u64) {
    if task.status == QueryStatus::Active && now_ms >= task.query.expires_at_ms {
        task.status = QueryStatus::Expired;
        task.actions.clear();
        task.pending_contacts.clear();
        task.pending_peers.clear();
        task.pending_dht_terms.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asl_types::protocol::{ConstraintOperator, TypedValue};
    fn peer(seed: u8) -> PeerId {
        let key = libp2p_identity::Keypair::ed25519_from_bytes([seed; 32]).expect("fixed key");
        PeerId::from_bytes(key.public().to_peer_id().to_bytes()).unwrap()
    }

    fn task(scope: QueryScope) -> OutgoingTask {
        OutgoingTask::new(
            1_000,
            Intent::FindEvidence,
            vec![ConceptRef::RUST],
            vec![Constraint {
                predicate: ConceptRef::RUST,
                operator: ConstraintOperator::Equal,
                value: TypedValue::Concept(ConceptRef::RUST),
            }],
            ResultShape::Claims,
            3,
            scope,
        )
    }

    #[test]
    fn contacts_are_dispatched_before_public_dht_terms() {
        let mut router = QueryRouter::with_contacts([peer(1), peer(2)]);
        let task_id = router.start_query(task(QueryScope::Public)).unwrap();
        let actions = router.next_actions(&task_id, 1_001);
        assert_eq!(actions.len(), 2);
        assert!(
            actions
                .iter()
                .all(|action| matches!(action, QueryAction::Contact { .. }))
        );

        for action in actions {
            let QueryAction::Contact { peer_id, .. } = action else {
                unreachable!()
            };
            router.complete_peer(&task_id, &peer_id, 1_002).unwrap();
        }
        let actions = router.next_actions(&task_id, 1_003);
        assert_eq!(
            actions,
            vec![QueryAction::DhtLookup {
                task_id: task_id.clone(),
                concept: ConceptRef::RUST
            }]
        );
    }

    #[test]
    fn contacts_only_never_emits_a_dht_lookup() {
        let mut router = QueryRouter::with_contacts([peer(1)]);
        let task_id = router.start_query(task(QueryScope::ContactsOnly)).unwrap();
        let actions = router.next_actions(&task_id, 1_001);
        let QueryAction::Contact { peer_id, .. } = &actions[0] else {
            unreachable!()
        };
        router.complete_peer(&task_id, peer_id, 1_002).unwrap();
        assert!(router.next_actions(&task_id, 1_003).is_empty());
    }

    #[test]
    fn dht_providers_are_deduplicated_and_capped_at_sixteen_peers() {
        let mut router = QueryRouter::new();
        let task_id = router.start_query(task(QueryScope::Public)).unwrap();
        let actions = router.next_actions(&task_id, 1_001);
        assert_eq!(actions.len(), 1);
        let QueryAction::DhtLookup { concept, .. } = actions[0] else {
            unreachable!()
        };
        let providers = (0..20).map(peer).collect::<Vec<_>>();
        router
            .record_dht_result(&task_id, concept, providers.clone(), 1_002)
            .unwrap();
        let actions = router.next_actions(&task_id, 1_003);
        assert_eq!(actions.len(), MAX_QUERY_PEERS);
        let unique = actions
            .iter()
            .map(|action| match action {
                QueryAction::Contact { peer_id, .. } => peer_id,
                QueryAction::DhtLookup { .. } => unreachable!(),
            })
            .collect::<HashSet<_>>();
        assert_eq!(unique.len(), MAX_QUERY_PEERS);
    }

    #[test]
    fn expired_tasks_do_not_dispatch_late_actions() {
        let mut router = QueryRouter::with_contacts([peer(1)]);
        let task_id = router
            .start_query(task(QueryScope::Public).with_expiry(2_000))
            .unwrap();
        assert!(router.next_actions(&task_id, 2_000).is_empty());
        assert_eq!(router.status(&task_id), Some(QueryStatus::Expired));
    }

    #[test]
    fn inbound_replay_is_executed_once_and_never_forwarded() {
        let mut router = QueryRouter::new();
        let query = task(QueryScope::Public).query(Id128([7; 16]), Id128([8; 16]));
        let remote = peer(9);
        assert!(matches!(
            router.accept_incoming(remote.clone(), query.clone(), 1_001),
            Ok(InboundQueryDecision::ExecuteLocally { .. })
        ));
        assert_eq!(
            router.accept_incoming(remote, query, 1_002).unwrap(),
            InboundQueryDecision::Duplicate
        );
        assert!(
            router
                .next_actions(&TaskId(Id128([7; 16])), 1_003)
                .is_empty()
        );
    }
}
