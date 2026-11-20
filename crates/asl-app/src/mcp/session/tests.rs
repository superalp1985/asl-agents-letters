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
            }))
            .await,
        Err(ErrorCode::NotFound)
    );
    assert_eq!(
        session
            .call(Request::Fetch(FetchArgs {
                task_id: task_id.clone(),
                offer_id
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
        })
    };
    session.tasks[0].offers[0].offer.expires_at_ms = 0;
    assert_eq!(session.call(fetch()).await, Err(ErrorCode::Timeout));
    assert!(session.tasks[0].offers[0].download.is_none());
    session.tasks[0].offers[0].offer.expires_at_ms = unix_time_ms().unwrap() + QUERY_WINDOW_MS;
    assert_eq!(session.call(fetch()).await, Err(ErrorCode::Timeout));
    let status = session.report(&task_id, false).unwrap();
    assert_eq!(status["downloads"][0]["status"], "queued");
    assert!(status["downloads"][0]["transfer_id"].is_null());

    let entry = &mut session.tasks[0].offers[0];
    entry.offer.expires_at_ms = 0;
    let transfer = TransferId(Id128([7; 16]));
    entry
        .download
        .as_mut()
        .unwrap()
        .accept(DownloadEvent::AwaitingApproval {
            approval_id: Id128([8; 16]),
            transfer_id: transfer.clone(),
        });
    let pending = session.call(fetch()).await.unwrap();
    assert_eq!(pending["transfer_id"], hex::encode(transfer.0.as_bytes()));
    assert_eq!(pending["status"], "awaiting_approval");
    assert!(pending.get("approval_id").is_none());

    let entry = &mut session.tasks[0].offers[0];
    entry
        .download
        .as_mut()
        .unwrap()
        .accept(DownloadEvent::Completed(DownloadInfo {
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
