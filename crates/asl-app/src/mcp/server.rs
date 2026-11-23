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
    sync::{broadcast, oneshot},
    time::{Instant, MissedTickBehavior, interval, sleep, sleep_until, timeout},
};

use crate::{
    OutgoingQueryPort,
    agent_mail::{InboxDecision, MailEvent, MailPort},
    downloads::DownloadPort,
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
        Self::start(root, grant, queries, downloads, None, None)
    }

    pub fn spawn_with_mail(
        root: PathBuf,
        grant: HostGrant,
        queries: OutgoingQueryPort,
        downloads: DownloadPort,
        mail: MailPort,
        recovery: Option<Recovery>,
    ) -> Result<Self, AslError> {
        Self::start(root, grant, queries, downloads, Some(mail), recovery)
    }

    fn start(
        root: PathBuf,
        grant: HostGrant,
        queries: OutgoingQueryPort,
        downloads: DownloadPort,
        mail: Option<MailPort>,
        recovery: Option<Recovery>,
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
                                let legacy = listen(&mut listener, &grant, &queries, &downloads, mail.as_ref(), None);
                                if let (Some(listener), Some(recovery)) = (&mut recovery_listener, recovery.as_ref()) {
                                    let recovery = listen(listener, &grant, &queries, &downloads, None, Some(recovery));
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
                    Request::LocalCapabilities => Ok(json!({
                        "send_expression": !is_recovery && grant.expressions && mail.is_some(),
                        "receive_offer": push && mail.is_some(),
                        "task_recovery": is_recovery,
                        "recovery_query": is_recovery,
                        "recovery_results": is_recovery && grant.recovery_results,
                        "recovery_download": is_recovery,
                        "recovery_download_decision": is_recovery,
                    })),
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
                    Request::SendExpression(_) | Request::Fetch(_) | Request::ReceiveOffer(_)
                        if is_recovery => Err(ErrorCode::PolicyDenied),
                    Request::SendExpression(args) => send_expression(mail, grant, args).await,
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
            && event["kind"] == "file_offer"
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
