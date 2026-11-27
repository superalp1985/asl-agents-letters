use std::{
    collections::{HashMap, VecDeque},
    sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use asl_agent::{
    ActQuestion, ActReplyError, ActReplyPlan, gateway::HttpModelGateway, generate_act_reply,
};
use asl_policy::{AccessRequest, Permit, PolicyRevision, PolicyService};
use asl_store::{Store, budgets::BudgetKind};
use asl_types::{
    error::AslError,
    ids::{Hash32, Id128},
    protocol::{Act, ActType},
    task::GrantId,
};

use crate::model_endpoint_access::{ModelEndpointAccess, configured_model_gateway};

use super::auto_reply_evidence::AutoReplyEvidenceContext;
use super::{Supervisor, groups::LocalGroupAction, unix_time_ms};

const MAX_QUEUED_REPLIES: usize = 8;
const MAX_RECENT_REQUESTS: usize = 256;
const MAX_MODEL_CALLS_PER_MINUTE: usize = 6;
const CONVERSATION_COOLDOWN: Duration = Duration::from_secs(5);

pub(super) struct AutoReplyRuntime {
    jobs: SyncSender<Job>,
    results: Receiver<JobResult>,
    _worker: JoinHandle<()>,
    queued: usize,
    recent: VecDeque<Id128>,
    recent_set: HashMap<Id128, ()>,
    cooldowns: HashMap<Id128, Instant>,
    model_calls: VecDeque<Instant>,
}

struct Job {
    room: Hash32,
    request: ActQuestion,
    evidence: Option<AutoReplyEvidenceContext>,
}

enum JobResult {
    Ready {
        room: Hash32,
        request: ActQuestion,
        plan: ActReplyPlan,
        elapsed_ms: u64,
    },
    Failed,
}

impl AutoReplyRuntime {
    pub(super) fn spawn(paths: &crate::paths::AppPaths) -> Result<Self, AslError> {
        let gateway = configured_model_gateway(paths).map_err(|_| AslError::InvalidPolicyState)?;
        let access = ModelEndpointAccess::new(paths);
        let (jobs, job_rx) = mpsc::sync_channel(MAX_QUEUED_REPLIES);
        let (result_tx, results) = mpsc::sync_channel(MAX_QUEUED_REPLIES);
        let worker = thread::Builder::new()
            .name("asl-act-reply".into())
            .spawn(move || worker_loop(gateway, access, job_rx, result_tx))
            .map_err(AslError::Io)?;
        Ok(Self {
            jobs,
            results,
            _worker: worker,
            queued: 0,
            recent: VecDeque::new(),
            recent_set: HashMap::new(),
            cooldowns: HashMap::new(),
            model_calls: VecDeque::new(),
        })
    }

    fn enqueue(
        &mut self,
        room: Hash32,
        request: ActQuestion,
        evidence: Option<AutoReplyEvidenceContext>,
        now: Instant,
    ) -> bool {
        self.model_calls
            .retain(|started| now.saturating_duration_since(*started) < Duration::from_secs(60));
        if self.recent_set.contains_key(&request.message_id)
            || self.queued >= MAX_QUEUED_REPLIES
            || self.model_calls.len() >= MAX_MODEL_CALLS_PER_MINUTE
            || self
                .cooldowns
                .get(&request.conversation_id)
                .is_some_and(|until| now < *until)
        {
            return false;
        }
        match self.jobs.try_send(Job {
            room,
            request,
            evidence,
        }) {
            Ok(()) => {
                self.queued += 1;
                self.model_calls.push_back(now);
                true
            }
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => false,
        }
    }

    fn remember(&mut self, request_id: Id128, conversation_id: Id128, now: Instant) {
        if self.recent.len() == MAX_RECENT_REQUESTS
            && let Some(expired) = self.recent.pop_front()
        {
            self.recent_set.remove(&expired);
        }
        self.recent_set.insert(request_id, ());
        self.recent.push_back(request_id);
        self.cooldowns
            .insert(conversation_id, now + CONVERSATION_COOLDOWN);
        self.cooldowns
            .retain(|_, until| *until > now.checked_sub(Duration::from_secs(60)).unwrap_or(now));
    }
}

pub(super) fn queue_auto_reply(
    runtime: &mut AutoReplyRuntime,
    room: Hash32,
    act: &Act,
    evidence: Option<AutoReplyEvidenceContext>,
    store: &Store,
    now_ms: u64,
) {
    if act.act_type != ActType::Ask || act.nl_body.is_none() {
        return;
    }
    let Ok(request) = ActQuestion::from_act(act) else {
        return;
    };
    let conversation = alloy_primitives::hex::encode(act.conversation_id.0);
    if !store
        .resource_budget_available(&conversation, BudgetKind::ModelCalls, now_ms)
        .unwrap_or(false)
        || !store
            .resource_budget_available(&conversation, BudgetKind::CpuMs, now_ms)
            .unwrap_or(false)
    {
        return;
    }
    let now = Instant::now();
    if runtime.enqueue(room, request, evidence, now) {
        let _ = store.consume_resource_budget(&conversation, BudgetKind::ModelCalls, 1, now_ms);
        runtime.remember(act.message_id, act.conversation_id, now);
    }
}

impl Supervisor {
    pub(super) fn poll_auto_act_replies(&mut self) -> Result<(), AslError> {
        loop {
            let result = match self.auto_reply.results.try_recv() {
                Ok(result) => result,
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => return Ok(()),
            };
            self.auto_reply.queued = self.auto_reply.queued.saturating_sub(1);
            let JobResult::Ready {
                room,
                request,
                plan,
                elapsed_ms,
            } = result
            else {
                continue;
            };
            if let Some(groups) = &self.groups {
                let conversation = alloy_primitives::hex::encode(request.conversation_id.0);
                let _ = groups.store.consume_resource_budget(
                    &conversation,
                    BudgetKind::CpuMs,
                    elapsed_ms.max(1),
                    unix_time_ms()?,
                );
            }
            if !self.groups.as_ref().is_some_and(|groups| {
                asl_store::group_state::GroupInboundPolicy::load(&groups.store)
                    .is_ok_and(|policy| policy.answer_enabled)
            }) {
                continue;
            }
            let reply_id = Id128(super::fresh_id()?);
            let Ok(act) = asl_agent::build_act_reply(reply_id, &request, &plan) else {
                continue;
            };
            let now = unix_time_ms()?;
            let _ = self.apply_local_group_action(
                LocalGroupAction::SendApplication {
                    room,
                    application: Box::new(asl_groups::GroupApplication::Act(act)),
                },
                now,
            );
        }
    }
}

fn worker_loop(
    gateway: HttpModelGateway,
    access: ModelEndpointAccess,
    jobs: Receiver<Job>,
    results: SyncSender<JobResult>,
) {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return;
    };
    while let Ok(Job {
        room,
        request,
        evidence,
    }) = jobs.recv()
    {
        let started = Instant::now();
        let result = if let Some(context) = evidence {
            let provider = context.provider.clone();
            let (read_policy, model_policy) = context.policies();
            runtime.block_on(generate_act_reply(
                &gateway,
                &request,
                &provider,
                &context.evidence,
                &read_policy,
                &model_policy,
                || unix_time_ms().unwrap_or(0),
            ))
        } else {
            access
                .first_authorized()
                .ok()
                .flatten()
                .ok_or(ActReplyError::ProviderUnavailable)
                .and_then(|provider| {
                    runtime.block_on(generate_act_reply(
                        &gateway,
                        &request,
                        &provider,
                        &[],
                        &DataFreePolicy,
                        &DataFreePolicy,
                        || unix_time_ms().unwrap_or(0),
                    ))
                })
        };
        let event = match result {
            Ok(plan) => JobResult::Ready {
                room,
                request,
                plan,
                elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            },
            Err(_) => JobResult::Failed,
        };
        if results.send(event).is_err() {
            return;
        }
    }
}

struct DataFreePolicy;

impl PolicyService for DataFreePolicy {
    fn authorize(&self, _: &AccessRequest, _: u64) -> Result<Permit, AslError> {
        Err(AslError::PolicyDenied)
    }

    fn revalidate(&self, _: &Permit, _: u64) -> Result<(), AslError> {
        Err(AslError::PolicyDenied)
    }

    fn revoke(&self, _: GrantId, _: u64) -> Result<PolicyRevision, AslError> {
        Err(AslError::PolicyDenied)
    }
}
