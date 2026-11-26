use std::{
    collections::VecDeque,
    io,
    path::PathBuf,
    sync::mpsc,
    thread::{self, JoinHandle},
    time::Duration,
};

use asl_policy::LocalPipeServer;
use asl_types::error::{AslError, ErrorCode};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{broadcast, oneshot, watch},
    time::{Instant, MissedTickBehavior, interval, sleep, sleep_until, timeout},
};

use crate::{
    OutgoingQueryPort,
    agent_mail::{InboxDecision, MailEvent, MailPort},
    downloads::DownloadPort,
    network_identity::NetworkAdmissionStatus,
};

use super::{
    contract::{Request, ServerFrame, parse_id},
    grant::HostGrant,
    inbox::{Inbox, MAX_EVENTS},
    recovery::Recovery,
    secure::SecurePipe,
    session::{Session, error_code},
};

const IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const FIRST_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct McpWorker {
    stop: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl McpWorker {
    #[cfg(test)]
    pub fn spawn(
        root: PathBuf,
        grant: HostGrant,
        queries: OutgoingQueryPort,
        downloads: DownloadPort,
    ) -> Result<Self, AslError> {
        Self::start(root, grant, queries, downloads, None, None, None)
    }

    #[cfg(test)]
    pub fn spawn_with_mail(
        root: PathBuf,
        grant: HostGrant,
        queries: OutgoingQueryPort,
        downloads: DownloadPort,
        mail: MailPort,
        recovery: Option<Recovery>,
    ) -> Result<Self, AslError> {
        Self::start(root, grant, queries, downloads, Some(mail), recovery, None)
    }

    pub fn spawn_with_mail_and_readiness(
        root: PathBuf,
        grant: HostGrant,
        queries: OutgoingQueryPort,
        downloads: DownloadPort,
        mail: MailPort,
        recovery: Option<Recovery>,
        readiness: watch::Receiver<NetworkAdmissionStatus>,
    ) -> Result<Self, AslError> {
        Self::start(
            root,
            grant,
            queries,
            downloads,
            Some(mail),
            recovery,
            Some(readiness),
        )
    }

    fn start(
        root: PathBuf,
        grant: HostGrant,
        queries: OutgoingQueryPort,
        downloads: DownloadPort,
        mail: Option<MailPort>,
        recovery: Option<Recovery>,
        readiness: Option<watch::Receiver<NetworkAdmissionStatus>>,
    ) -> Result<Self, AslError> {
        let (ready, started) = mpsc::channel();
        let (stop, stopped) = oneshot::channel();
        let thread = thread::Builder::new()
            .name("asl-mcp-bridge".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready.send(Err(error.into()));
                        return;
                    }
                };
                runtime.block_on(async {
                    let mut listener = match LocalPipeServer::bind(&root) {
                        Ok(listener) => listener,
                        Err(error) => {
                            let _ = ready.send(Err(error));
                            return;
                        }
                    };
                    let mut recovery_listener = if recovery.is_some() {
                        match LocalPipeServer::bind_recovery(&root) {
                            Ok(listener) => Some(listener),
                            Err(error) => {
                                let _ = ready.send(Err(error));
                                return;
                            }
                        }
                    } else {
                        None
                    };
                    if ready.send(Ok(())).is_ok() {
                        tokio::select! {
                            _ = stopped => {}
                            _ = async {
                                let legacy = listen(&mut listener, &grant, &queries, &downloads, mail.as_ref(), None, readiness.as_ref());
                                if let (Some(listener), Some(recovery)) = (&mut recovery_listener, recovery.as_ref()) {
                                    let recovery = listen(listener, &grant, &queries, &downloads, None, Some(recovery), readiness.as_ref());
                                    tokio::join!(legacy, recovery);
                                } else {
                                    legacy.await;
                                }
                            } => {}
                        }
                    }
                });
            })?;
        let worker = Self {
            stop: Some(stop),
            thread: Some(thread),
        };
        started.recv().map_err(|_| AslError::SandboxUnavailable)??;
        Ok(worker)
    }
}

impl Drop for McpWorker {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

async fn listen(
    listener: &mut LocalPipeServer,
    grant: &HostGrant,
    queries: &OutgoingQueryPort,
    downloads: &DownloadPort,
    mail: Option<&MailPort>,
    recovery: Option<&Recovery>,
    readiness: Option<&watch::Receiver<NetworkAdmissionStatus>>,
) {
    loop {
        match listener.accept().await {
            Ok(mut connection) => {
                let _ = serve(
                    connection.stream(),
                    grant,
                    queries,
                    downloads,
                    mail,
                    recovery,
                    readiness,
                )
                .await;
            }
            Err(AslError::Io(error)) if error.kind() == io::ErrorKind::NotConnected => return,
            Err(_) => sleep(Duration::from_millis(50)).await,
        }
    }
}

async fn serve(
    stream: impl AsyncRead + AsyncWrite + Unpin,
    grant: &HostGrant,
    queries: &OutgoingQueryPort,
    downloads: &DownloadPort,
    mail: Option<&MailPort>,
    recovery: Option<&Recovery>,
    readiness: Option<&watch::Receiver<NetworkAdmissionStatus>>,
) -> Result<(), AslError> {
    let is_recovery = recovery.is_some();
    let key = if is_recovery {
        grant
            .recovery_key
            .as_deref()
            .ok_or(AslError::InvalidPolicyState)?
    } else {
        &grant.key
    };
    let mut pipe = SecurePipe::respond(stream, key).await?;
    let push = grant.agent_push && !is_recovery;
    let inbox = if is_recovery { None } else { grant.inbox };
    let capabilities = json!({
        "bootstrap_v1": readiness.is_some(),
        "send_expression": !is_recovery && grant.expressions && mail.is_some(),
        "send_context_expression": !is_recovery && grant.expressions && mail.is_some(),
        "send_act": !is_recovery && grant.expressions && mail.is_some(),
        "send_file": !is_recovery && grant.groups_admin && mail.is_some(),
        "groups_admin": !is_recovery && grant.groups_admin && mail.is_some(),
        "request_context": !is_recovery && grant.expressions && push && mail.is_some(),
        "confirm_context": !is_recovery && grant.expressions && push && mail.is_some(),
        "receive_offer": push && mail.is_some(),
        "task_recovery": is_recovery,
        "recovery_query": is_recovery,
        "recovery_results": is_recovery && grant.recovery_results,
        "recovery_download": is_recovery,
        "recovery_download_decision": is_recovery,
    });
    let mut session = Session::new(queries, downloads, grant.scope, inbox);
    session.recovery = recovery;
    let mut read_deadline = Instant::now() + FIRST_REQUEST_TIMEOUT;
    let mut updates = None;
    let mut subscribed = false;
    let mut pending = Inbox::default();
    let mut seen_offers = VecDeque::new();
    let mut permission: Option<InboxDecision> = None;
    let mut poll = interval(Duration::from_millis(50));
    poll.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        let frame = tokio::select! {
            biased;
            _ = sleep_until(read_deadline), if !subscribed => {
                return Err(AslError::ExpiredMessage);
            }
            request = pipe.receive::<Request>() => {
                let reply = match request? {
                    Request::AgentEventsAvailable => Ok(Value::Bool(push)),
                    Request::LocalCapabilities => Ok(capabilities.clone()),
                    Request::AgentBootstrap => readiness
                        .map(|status| super::bootstrap::report(
                            *status.borrow(),
                            grant.scope,
                            push,
                            is_recovery,
                            &capabilities,
                        ))
                        .ok_or(ErrorCode::IncompatibleVersion),
                    Request::RecoveryTask(args) => {
                        session.refresh_recovery()?;
                        recovery.ok_or(ErrorCode::PolicyDenied).and_then(|r| r.task(&args.task_id))
                    }
                    Request::RecoveryResult(args) => {
                        session.refresh_recovery()?;
                        recovery.ok_or(ErrorCode::PolicyDenied).and_then(|r| r.result(&args.task_id))
                    }
                    Request::RecoveryDownload(args) => recovery.ok_or(ErrorCode::PolicyDenied)
                        .and_then(|r| r.download(downloads, args)),
                    Request::RecoveryDownloadDecision(args) => recovery.ok_or(ErrorCode::PolicyDenied)
                        .and_then(|r| r.download_decision(&args.approval_id)),
                    Request::RecoveryEvents(args) => {
                        session.refresh_recovery()?;
                        recovery.ok_or(ErrorCode::PolicyDenied).and_then(|r| r.events(args.after))
                    }
                    Request::SubscribeAgentEvents if push => {
                        if !subscribed {
                            session.watch(&mut Inbox::default());
                            updates = mail.map(MailPort::subscribe);
                            subscribed = true;
                        }
                        Ok(Value::Null)
                    }
                    Request::UnsubscribeAgentEvents if push => {
                        updates = None;
                        subscribed = false;
                        pending = Inbox::default();
                        seen_offers.clear();
                        permission = None;
                        session.inbox = inbox;
                        Ok(Value::Null)
                    }
                    Request::SubscribeAgentEvents | Request::UnsubscribeAgentEvents => {
                        Err(ErrorCode::PolicyDenied)
                    }
                    Request::SendExpression(_)
                    | Request::SendContextExpression(_)
                    | Request::SendAct(_)
                    | Request::SendFile(_)
                    | Request::GroupList
                    | Request::GroupCreate
                    | Request::GroupMembers(_)
                    | Request::GroupSetAccess(_)
                    | Request::GroupInvite(_)
                    | Request::GroupInviteRequest(_)
                    | Request::DirectOpen(_)
                    | Request::RenewActBudget(_)
                    | Request::RequestContext(_)
                    | Request::ConfirmContext(_)
                    | Request::Fetch(_)
                    | Request::ReceiveOffer(_)
                        if is_recovery => Err(ErrorCode::PolicyDenied),
                    Request::SendExpression(args) => send_expression(mail, grant, args).await,
                    Request::SendContextExpression(args) => {
                        send_context_expression(mail, grant, args).await
                    }
                    Request::SendAct(args) => send_act(mail, grant, args).await,
                    Request::SendFile(args) => send_file(mail, grant, args).await,
                    Request::GroupList => group_list(mail, grant).await,
                    Request::GroupCreate => group_create(mail, grant).await,
                    Request::GroupMembers(args) => group_members(mail, grant, args).await,
                    Request::GroupSetAccess(args) => group_set_access(mail, grant, args).await,
                    Request::GroupInvite(args) => group_invite(mail, grant, args).await,
                    Request::GroupInviteRequest(args) => {
                        group_invite_request(mail, grant, args).await
                    }
                    Request::DirectOpen(args) => direct_open(mail, grant, args).await,
                    Request::RenewActBudget(args) => {
                        renew_act_budget(mail, grant, args).await
                    }
                    Request::RequestContext(args) if subscribed => {
                        request_context(mail, grant, args).await
                    }
                    Request::RequestContext(_) => Err(ErrorCode::PolicyDenied),
                    Request::ConfirmContext(args) if subscribed => {
                        confirm_context(mail, args).await
                    }
                    Request::ConfirmContext(_) => Err(ErrorCode::PolicyDenied),
                    Request::Fetch(args) if subscribed && session.inbox.is_none() => {
                        match (session.check_task_offer(&args), mail) {
                            (Ok(()), Some(mail)) => request_permission(&mut permission, mail.request_task_inbox()).await,
                            (Err(code), _) => Err(code),
                            _ => Err(ErrorCode::PolicyDenied),
                        }
                    }
                    Request::ReceiveOffer(args) => {
                        let id = parse_id(&args.offer_id);
                        match (id, mail, session.inbox) {
                            (Ok(id), Some(mail), Some(inbox)) if subscribed && seen_offers.contains(&id) => {
                                session.receive_offer(mail, id, inbox).await
                            }
                            (Ok(id), Some(mail), None) if subscribed && seen_offers.contains(&id) => {
                                request_permission(&mut permission, mail.request_inbox(id, grant.scope)).await
                            }
                            (Err(code), _, _) => Err(code),
                            _ => Err(ErrorCode::PolicyDenied),
                        }
                    }
                    request => session.call(request).await,
                };
                read_deadline = Instant::now() + IDLE_TIMEOUT;
                ServerFrame::Reply(reply)
            }
            frame = pending_frame(&mut pending), if subscribed => frame,
            decision = async { permission.as_mut().expect("guarded pending permission").await }, if permission.is_some() => {
                permission = None;
                let decision = decision.unwrap_or(Err(AslError::SandboxUnavailable));
                let status = match decision {
                    Ok(inbox) => { session.inbox = Some(inbox); json!({"status":"granted"}) }
                    Err(error) => json!({"status":"not_granted","error_code":error_code(error)}),
                };
                pending.push(json!({"kind":"inbox_permission","details":status}));
                continue;
            }
            _ = poll.tick(), if subscribed || (is_recovery && session.has_live_recovery_tasks()) => {
                if subscribed { session.watch(&mut pending); }
                else { session.refresh_recovery()?; }
                continue;
            }
            event = next_event(&mut updates) => {
                match event {
                    Ok(mut event) => {
                        if let Some(details) = event.details.as_object_mut()
                            && details.contains_key("offer_id")
                        {
                            details.insert("inbox_permission_required".into(), Value::Bool(session.inbox.is_none()));
                        }
                        pending.push(json!({ "kind": event.kind, "details": event.details }));
                    }
                    Err(broadcast::error::RecvError::Lagged(count)) => pending.lose(count),
                    Err(broadcast::error::RecvError::Closed) => updates = None,
                }
                continue;
            }
        };
        if let ServerFrame::AgentEvent { event } = &frame
            && matches!(
                event["kind"].as_str(),
                Some("file_offer" | "context_file_offer")
            )
            && let Some(id) = event["details"]["offer_id"]
                .as_str()
                .and_then(|id| parse_id(id).ok())
            && !seen_offers.contains(&id)
        {
            if seen_offers.len() == MAX_EVENTS {
                seen_offers.pop_front();
            }
            seen_offers.push_back(id);
        }
        timeout(RESPONSE_TIMEOUT, pipe.send(&frame))
            .await
            .map_err(|_| AslError::ExpiredMessage)??;
    }
}

async fn request_permission(
    pending: &mut Option<InboxDecision>,
    request: impl Future<Output = Result<InboxDecision, AslError>>,
) -> Result<Value, ErrorCode> {
    if pending.is_none() {
        *pending = Some(request.await.map_err(error_code)?);
    }
    Ok(json!({"status":"inbox_permission_required"}))
}

async fn next_event(
    updates: &mut Option<broadcast::Receiver<MailEvent>>,
) -> Result<MailEvent, broadcast::error::RecvError> {
    let Some(updates) = updates else {
        return std::future::pending().await;
    };
    updates.recv().await
}

async fn pending_frame(inbox: &mut Inbox) -> ServerFrame {
    match inbox.next() {
        Some(frame) => frame,
        None => std::future::pending().await,
    }
}

async fn send_expression(
    mail: Option<&MailPort>,
    grant: &HostGrant,
    args: super::contract::ExpressionArgs,
) -> Result<Value, ErrorCode> {
    let mail = mail
        .filter(|_| grant.expressions)
        .ok_or(ErrorCode::PolicyDenied)?;
    let (target, root, expression) = args.validate()?;
    let id = mail
        .send_expression(grant.scope, target, root, expression)
        .await
        .map_err(error_code)?;
    Ok(json!({ "message_id": alloy_primitives::hex::encode(id.0) }))
}

async fn send_context_expression(
    mail: Option<&MailPort>,
    grant: &HostGrant,
    args: super::contract::ContextExpressionArgs,
) -> Result<Value, ErrorCode> {
    let mail = mail
        .filter(|_| grant.expressions)
        .ok_or(ErrorCode::PolicyDenied)?;
    let (target, root, expression, required_contexts) = args.validate()?;
    let id = mail
        .send_context_expression(grant.scope, target, root, expression, required_contexts)
        .await
        .map_err(error_code)?;
    Ok(json!({ "message_id": alloy_primitives::hex::encode(id.0) }))
}

async fn send_act(
    mail: Option<&MailPort>,
    grant: &HostGrant,
    args: super::contract::ActArgs,
) -> Result<Value, ErrorCode> {
    let mail = mail
        .filter(|_| grant.expressions)
        .ok_or(ErrorCode::PolicyDenied)?;
    let (room, act) = args.validate()?;
    let id = mail.send_act(room, act).await.map_err(error_code)?;
    Ok(json!({ "message_id": alloy_primitives::hex::encode(id.0) }))
}

async fn send_file(
    mail: Option<&MailPort>,
    grant: &HostGrant,
    args: super::contract::SendFileArgs,
) -> Result<Value, ErrorCode> {
    let mail = mail
        .filter(|_| grant.groups_admin)
        .ok_or(ErrorCode::PolicyDenied)?;
    let (room, content_id, media_kind, concepts) = args.validate()?;
    mail.send_file(room, content_id, media_kind, concepts)
        .await
        .map_err(error_code)
}

async fn group_list(mail: Option<&MailPort>, grant: &HostGrant) -> Result<Value, ErrorCode> {
    let mail = mail
        .filter(|_| grant.groups_admin)
        .ok_or(ErrorCode::PolicyDenied)?;
    mail.group_list().await.map_err(error_code)
}

async fn group_create(mail: Option<&MailPort>, grant: &HostGrant) -> Result<Value, ErrorCode> {
    let mail = mail
        .filter(|_| grant.groups_admin)
        .ok_or(ErrorCode::PolicyDenied)?;
    mail.group_create().await.map_err(error_code)
}

async fn group_members(
    mail: Option<&MailPort>,
    grant: &HostGrant,
    args: super::contract::GroupRoomArgs,
) -> Result<Value, ErrorCode> {
    let mail = mail
        .filter(|_| grant.groups_admin)
        .ok_or(ErrorCode::PolicyDenied)?;
    let room = args.validate()?;
    mail.group_members(room).await.map_err(error_code)
}

async fn group_set_access(
    mail: Option<&MailPort>,
    grant: &HostGrant,
    args: super::contract::GroupSetAccessArgs,
) -> Result<Value, ErrorCode> {
    let mail = mail
        .filter(|_| grant.groups_admin)
        .ok_or(ErrorCode::PolicyDenied)?;
    let (room, update) = args.validate()?;
    mail.group_set_access(room, update)
        .await
        .map_err(error_code)
}

async fn group_invite(
    mail: Option<&MailPort>,
    grant: &HostGrant,
    args: super::contract::GroupInviteArgs,
) -> Result<Value, ErrorCode> {
    let mail = mail
        .filter(|_| grant.groups_admin)
        .ok_or(ErrorCode::PolicyDenied)?;
    let (room, agent) = args.validate()?;
    mail.group_invite(room, agent).await.map_err(error_code)
}

async fn group_invite_request(
    mail: Option<&MailPort>,
    grant: &HostGrant,
    args: super::contract::GroupInviteRequestArgs,
) -> Result<Value, ErrorCode> {
    let mail = mail
        .filter(|_| grant.groups_admin)
        .ok_or(ErrorCode::PolicyDenied)?;
    let (room, owner) = args.validate()?;
    mail.group_invite_request(room, owner)
        .await
        .map_err(error_code)
}

async fn direct_open(
    mail: Option<&MailPort>,
    grant: &HostGrant,
    args: super::contract::AgentTargetArgs,
) -> Result<Value, ErrorCode> {
    let mail = mail
        .filter(|_| grant.groups_admin)
        .ok_or(ErrorCode::PolicyDenied)?;
    let agent = args.validate()?;
    mail.direct_open(agent).await.map_err(error_code)
}

async fn renew_act_budget(
    mail: Option<&MailPort>,
    grant: &HostGrant,
    args: super::contract::RenewActBudgetArgs,
) -> Result<Value, ErrorCode> {
    let mail = mail
        .filter(|_| grant.groups_admin)
        .ok_or(ErrorCode::PolicyDenied)?;
    let (conversation_id, additional_messages, window_ms) = args.validate()?;
    mail.renew_act_budget(conversation_id, additional_messages, window_ms)
        .await
        .map_err(error_code)
}

async fn request_context(
    mail: Option<&MailPort>,
    grant: &HostGrant,
    args: super::contract::ContextRequestArgs,
) -> Result<Value, ErrorCode> {
    let mail = mail
        .filter(|_| grant.expressions && grant.agent_push)
        .ok_or(ErrorCode::PolicyDenied)?;
    let (target, reference) = args.validate()?;
    let id = mail
        .request_context(grant.scope, target, reference)
        .await
        .map_err(error_code)?;
    Ok(json!({ "request_id": alloy_primitives::hex::encode(id.0) }))
}

async fn confirm_context(
    mail: Option<&MailPort>,
    args: super::contract::ConfirmContextArgs,
) -> Result<Value, ErrorCode> {
    let mail = mail.ok_or(ErrorCode::PolicyDenied)?;
    let request_id = parse_id(&args.request_id)?;
    let (message_id, status) = mail.confirm_context(request_id).await.map_err(error_code)?;
    Ok(json!({
        "message_id": alloy_primitives::hex::encode(message_id.0),
        "status": match status {
            asl_types::protocol::ContextAgreementStatus::Conformant => "conformant",
            asl_types::protocol::ContextAgreementStatus::Unresolved => "unresolved",
            asl_types::protocol::ContextAgreementStatus::Rejected => "rejected",
        },
    }))
}
