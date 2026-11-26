use asl_types::ids::{AgentId, Hash32, PeerId};

use super::*;
use crate::{
    direct_outbound::outgoing_query_channel,
    downloads::{DownloadInfo, download_channel},
    mcp::contract::{QueryAudience, QueryIntent, QueryShape, QuerySpec, TaskArgs},
};

fn args() -> QueryArgs {
    QueryArgs {
        query: QuerySpec {
            intent: QueryIntent::LocateResource,
            result_shape: QueryShape::Resources,
        },
        terms: vec![(1, 101)],
        audience: QueryAudience::ContactsOnly,
        deadline_ms: QUERY_WINDOW_MS,
    }
}

#[test]
fn received_answer_survives_reopen_but_not_disabling_retention() {
    use crate::mcp::grant::{HostGrant, Key};
    use asl_types::protocol::{Answer, AnswerStatus, ResultStatus};

    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("recovery.sqlite3");
    let mut grant = HostGrant {
        key: Key::new([1; 32]),
        recovery_key: Some(Key::new([2; 32])),
        recovery_results: true,
        scope: QueryScope::ContactsOnly,
        inbox: None,
        agent_push: false,
        expressions: false,
        groups_admin: false,
        act_history: false,
    };
    let recovery = Recovery::configure(&path, Some(&grant)).unwrap().unwrap();
    let (queries, _query_runtime) = outgoing_query_channel();
    let (downloads, _download_runtime) = download_channel();
    let mut session = Session::new(&queries, &downloads, QueryScope::ContactsOnly, None);
    session.recovery = Some(&recovery);
    let query = session.query(args()).unwrap();
    let local_id = query["task_id"].as_str().unwrap();
    let network_id = TaskId(Id128([3; 16]));
    session.tasks[0].accept(OutgoingQueryEvent::TaskStarted {
        task_id: network_id.clone(),
    });
    session.refresh_recovery().unwrap();

    let mut peer = vec![0x12, 0x20];
    peer.extend([4; 32]);
    let now = unix_time_ms().unwrap();
    session.tasks[0].accept(OutgoingQueryEvent::Response {
        task_id: network_id.clone(),
        agent_id: AgentId([5; 32]),
        peer_id: PeerId::from_bytes(peer).unwrap(),
        frame: Box::new(WireFrame::Answer(Answer {
            message_id: Id128([6; 16]),
            root_task_id: network_id.0,
            status: AnswerStatus::Answered,
            claims: vec![Claim {
                subject: TypedValue::Concept(ConceptRef::RUST),
                predicate: ConceptRef::RUST,
                object: TypedValue::Integer(42),
                evidence: None,
            }],
            evidence_ids: vec![],
            result_status: ResultStatus::Partial,
            created_at_ms: now,
            expires_at_ms: now + QUERY_WINDOW_MS,
        })),
    });
    session.refresh_recovery().unwrap();
    let active = recovery.result(local_id).unwrap();
    assert_eq!(active["status"], "active");
    assert_eq!(active["answers"][0]["claims"][0]["object"]["value"], 42);
    session.tasks[0].accept(OutgoingQueryEvent::TaskFinished {
        task_id: network_id,
        status: QueryStatus::Complete,
    });
    drop(session);
    drop(recovery);

    let recovery = Recovery::configure(&path, Some(&grant)).unwrap().unwrap();
    let complete = recovery.result(local_id).unwrap();
    assert_eq!(complete["status"], "complete");
    assert_eq!(complete["answers"], active["answers"]);
    assert!(complete.get("offers").is_none());
    assert!(complete.get("downloads").is_none());
    drop(recovery);

    grant.recovery_results = false;
    let recovery = Recovery::configure(&path, Some(&grant)).unwrap().unwrap();
    assert_eq!(recovery.result(local_id), Err(ErrorCode::PolicyDenied));
    assert_eq!(recovery.task(local_id).unwrap()["status"], "complete");
    drop(recovery);
    grant.recovery_results = true;
    let recovery = Recovery::configure(&path, Some(&grant)).unwrap().unwrap();
    let cleared = recovery.result(local_id).unwrap();
    assert_eq!(cleared["recorded"], false);
    assert_eq!(cleared["answers"], json!([]));
}

fn offer_response(task_id: TaskId, root: Id128) -> OutgoingQueryEvent {
    let mut encoded_peer = vec![0x12, 0x20];
    encoded_peer.extend([2; 32]);
    OutgoingQueryEvent::Response {
        task_id,
        agent_id: AgentId([3; 32]),
        peer_id: PeerId::from_bytes(encoded_peer).unwrap(),
        frame: Box::new(WireFrame::Offer(Offer {
            message_id: Id128([4; 16]),
            root_task_id: root,
            content_id: Hash32([5; 32]),
            file_size: 32,
            media_kind: MediaKind::Document,
            concepts: vec![ConceptRef::RUST],
            expires_at_ms: unix_time_ms().unwrap() + QUERY_WINDOW_MS,
        })),
    }
}

#[test]
fn core_checks_query_bounds_and_audience() {
    let (queries, _query_runtime) = outgoing_query_channel();
    let (downloads, _download_runtime) = download_channel();
    let mut session = Session::new(&queries, &downloads, QueryScope::ContactsOnly, None);

    for terms in [
        vec![],
        vec![(1, 101); 13],
        vec![(1, 101); 2],
        vec![(2, 101)],
    ] {
        assert_eq!(
            session.query(QueryArgs { terms, ..args() }),
            Err(ErrorCode::InvalidMessage)
        );
    }
    for deadline_ms in [0, QUERY_WINDOW_MS + 1] {
        assert_eq!(
            session.query(QueryArgs {
                deadline_ms,
                ..args()
            }),
            Err(ErrorCode::InvalidMessage)
        );
    }
    assert_eq!(
        session.query(QueryArgs {
            audience: QueryAudience::Public,
            ..args()
        }),
        Err(ErrorCode::PolicyDenied)
    );
    assert!(session.tasks.is_empty());
    let terms = (100..112).map(|id| (1, id)).collect();
    assert!(
        session
            .query(QueryArgs {
                terms,
                deadline_ms: 1,
                ..args()
            })
            .is_ok()
    );
}

#[tokio::test]
async fn offers_and_lookup_stay_in_their_correlated_task_and_session() {
    let (queries, _query_runtime) = outgoing_query_channel();
    let (downloads, _download_runtime) = download_channel();
    let mut session = Session::new(&queries, &downloads, QueryScope::Public, None);
    let result = session.call(Request::Query(args())).await.unwrap();
    let task_id = result["task_id"].as_str().unwrap().to_owned();

    let root = Id128([1; 16]);
    let network_task = TaskId(root);
    let task = session.tasks.front_mut().unwrap();
    task.accept(OutgoingQueryEvent::TaskStarted {
        task_id: network_task.clone(),
    });
    task.accept(offer_response(TaskId(Id128([9; 16])), root));
    task.accept(offer_response(network_task.clone(), Id128([8; 16])));
    assert!(task.offers.is_empty());
    task.accept(offer_response(network_task.clone(), root));

    let status = session
        .call(Request::TaskStatus(TaskArgs {
            task_id: task_id.clone(),
        }))
        .await
        .unwrap();
    assert_eq!(status["status"], "active");
    let offer_id = status["offers"][0]["offer_id"].as_str().unwrap().to_owned();
    assert_ne!(task_id, hex::encode(root.0));
    assert_ne!(offer_id, hex::encode([4_u8; 16]));
    let other_task_id = session.query(args()).unwrap()["task_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        session
            .call(Request::Fetch(FetchArgs {
                task_id: other_task_id,
                offer_id: offer_id.clone(),
                additional_offer_ids: vec![],
            }))
            .await,
        Err(ErrorCode::NotFound)
    );
    assert_eq!(
        session
            .call(Request::Fetch(FetchArgs {
                task_id: task_id.clone(),
                offer_id,
                additional_offer_ids: vec![],
            }))
            .await,
        Err(ErrorCode::PolicyDenied)
    );
    assert_eq!(
        session
            .call(Request::Result(TaskArgs {
                task_id: task_id.clone()
            }))
            .await,
        Err(ErrorCode::Busy)
    );
    let mut another = Session::new(&queries, &downloads, QueryScope::Public, None);
    assert_eq!(
        another
            .call(Request::TaskStatus(TaskArgs { task_id }))
            .await,
        Err(ErrorCode::NotFound)
    );
}

#[tokio::test]
async fn timeout_keeps_the_submission_and_the_worker_transfer_id() {
    let (queries, _query_runtime) = outgoing_query_channel();
    let (downloads, _download_runtime) = download_channel();
    let mut session = Session::new(
        &queries,
        &downloads,
        QueryScope::Public,
        Some(Id128([6; 16])),
    );
    let task_id = session.query(args()).unwrap()["task_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let root = Id128([1; 16]);
    let task = session.tasks.front_mut().unwrap();
    task.accept(OutgoingQueryEvent::TaskStarted {
        task_id: TaskId(root),
    });
    task.accept(offer_response(TaskId(root), root));
    task.accept(OutgoingQueryEvent::TaskFinished {
        task_id: TaskId(root),
        status: QueryStatus::Complete,
    });
    let offer_id = hex::encode(task.offers[0].id.0);
    let fetch = || {
        Request::Fetch(FetchArgs {
            task_id: task_id.clone(),
            offer_id: offer_id.clone(),
            additional_offer_ids: vec![],
        })
    };
    session.tasks[0].offers[0].offer.expires_at_ms = 0;
    assert_eq!(session.call(fetch()).await, Err(ErrorCode::Timeout));
    assert!(session.tasks[0].downloads.is_empty());
    session.tasks[0].offers[0].offer.expires_at_ms = unix_time_ms().unwrap() + QUERY_WINDOW_MS;
    assert_eq!(session.call(fetch()).await, Err(ErrorCode::Timeout));
    let status = session.report(&task_id, false).unwrap();
    assert_eq!(status["downloads"][0]["status"], "queued");
    assert!(status["downloads"][0]["transfer_id"].is_null());

    session.tasks[0].offers[0].offer.expires_at_ms = 0;
    let transfer = TransferId(Id128([7; 16]));
    session.tasks[0].downloads[0].accept(DownloadEvent::AwaitingApproval {
        approval_id: Id128([8; 16]),
        transfer_id: transfer.clone(),
    });
    let pending = session.call(fetch()).await.unwrap();
    assert_eq!(pending["transfer_id"], hex::encode(transfer.0.as_bytes()));
    assert_eq!(pending["status"], "awaiting_approval");
    assert!(pending.get("approval_id").is_none());

    session.tasks[0].downloads[0].accept(DownloadEvent::Completed(DownloadInfo {
        transfer_id: transfer,
        task_id: TaskId(root),
        content_id: Hash32([5; 32]),
        file_size: 32,
        chunk_count: 1,
        durable_bytes: 32,
        state: "complete".into(),
        part_path: "private-part-path".into(),
        destination_path: "private-destination-path".into(),
    }));
    let result = session
        .call(Request::Result(TaskArgs { task_id }))
        .await
        .unwrap();
    assert_eq!(result["offers"], json!([]));
    assert_eq!(result["downloads"][0]["status"], "completed");
    assert_eq!(
        result["downloads"][0]["transfer_id"],
        pending["transfer_id"]
    );
    assert!(result["downloads"][0].get("resource_id").is_none());
    assert!(!result.to_string().contains("private-"));
}

#[test]
fn multi_offer_selection_rejects_invalid_sets_before_queueing_and_freezes_on_submit() {
    let (queries, _query_runtime) = outgoing_query_channel();
    let (port, _runtime) = download_channel();
    let inbox = Some(Id128([6; 16]));
    let mut session = Session::new(&queries, &port, QueryScope::ContactsOnly, inbox);
    session.query(args()).unwrap();
    let task = session.tasks.front_mut().unwrap();
    let root = Id128([1; 16]);
    task.accept(OutgoingQueryEvent::TaskStarted {
        task_id: TaskId(root),
    });
    for n in 0..6 {
        let mut event = offer_response(TaskId(root), root);
        let OutgoingQueryEvent::Response { peer_id, frame, .. } = &mut event else {
            unreachable!()
        };
        let WireFrame::Offer(offer) = frame.as_mut() else {
            unreachable!()
        };
        let mut bytes = peer_id.as_bytes().to_vec();
        *bytes.last_mut().unwrap() = if n == 4 { 0 } else { n };
        *peer_id = PeerId::from_bytes(bytes).unwrap();
        match n {
            1 => offer.content_id = Hash32([8; 32]),
            2 => offer.file_size += 1,
            3 => offer.expires_at_ms = 0,
            _ => {}
        }
        task.accept(event);
    }
    let ids: Vec<_> = task.offers.iter().map(|o| o.id).collect();
    for (other, reason) in [
        (ids[1], ErrorCode::InvalidMessage),
        (ids[2], ErrorCode::InvalidMessage),
        (ids[3], ErrorCode::Timeout),
        (ids[4], ErrorCode::InvalidMessage),
        (Id128([0; 16]), ErrorCode::NotFound),
    ] {
        assert_eq!(
            task.select_download(&port, inbox, vec![ids[0], other])
                .err(),
            Some(reason)
        );
    }
    assert!(task.downloads.is_empty());
    task.select_download(&port, inbox, vec![ids[0], ids[5]])
        .unwrap();
    task.offers[0].offer.expires_at_ms = 0;
    assert!(
        task.select_download(&port, inbox, vec![ids[5], ids[0]])
            .is_ok()
    );
    for changed in [
        vec![ids[5]],
        vec![ids[4], ids[5]],
        vec![ids[5], ids[0], ids[4]],
    ] {
        assert_eq!(
            task.select_download(&port, inbox, changed).err(),
            Some(ErrorCode::PolicyDenied)
        );
    }
    assert_eq!(task.downloads.len(), 1);
}

#[test]
fn large_evidence_is_structured_and_bounded() {
    let (queries, _query_runtime) = outgoing_query_channel();
    let (downloads, _download_runtime) = download_channel();
    let mut session = Session::new(&queries, &downloads, QueryScope::ContactsOnly, None);
    let task_id = session.query(args()).unwrap()["task_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let root = Id128([1; 16]);
    let task = session.tasks.front_mut().unwrap();
    task.accept(OutgoingQueryEvent::TaskStarted {
        task_id: TaskId(root),
    });
    let OutgoingQueryEvent::Response {
        agent_id, peer_id, ..
    } = offer_response(TaskId(root), root)
    else {
        unreachable!();
    };
    let concepts = TypedValue::Concepts(
        (1..=6)
            .chain(100..=111)
            .chain(200..=209)
            .map(|concept_id| ConceptRef {
                vocabulary_id: 1,
                concept_id,
            })
            .collect(),
    );
    task.accept(OutgoingQueryEvent::Response {
        task_id: TaskId(root),
        agent_id,
        peer_id,
        frame: Box::new(WireFrame::Answer(Answer {
            message_id: Id128([2; 16]),
            root_task_id: root,
            created_at_ms: 1,
            expires_at_ms: 2,
            status: AnswerStatus::Answered,
            claims: vec![
                Claim {
                    subject: concepts.clone(),
                    predicate: ConceptRef {
                        vocabulary_id: 1,
                        concept_id: 200
                    },
                    object: concepts,
                    evidence: Some(Hash32([5; 32])),
                };
                32
            ],
            evidence_ids: vec![Id128([3; 16])],
            result_status: ResultStatus::Unverified,
        })),
    });
    task.accept(OutgoingQueryEvent::TaskFinished {
        task_id: TaskId(root),
        status: QueryStatus::Expired,
    });
    let result = session.report(&task_id, true).unwrap();
    assert_eq!(result["status"], "expired");
    assert_eq!(result["answers_truncated"], true);
    assert_eq!(
        result["answers"][0]["claims"][0]["object"]["type"],
        "concepts"
    );
    assert!(serde_json::to_vec(&result["answers"]).unwrap().len() <= MAX_ANSWER_BYTES + 2);
}
