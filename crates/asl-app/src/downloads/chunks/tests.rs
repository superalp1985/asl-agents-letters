use std::fs;

use asl_net::codec::BulkResponse;
use asl_types::manifest::CHUNK_SIZE;

use super::*;
use crate::{
    downloads::{DownloadStart, test_inbox::Inbox},
    paths::AppPaths,
};

fn collect(local: &mut LocalDownloads, now: u64) -> (Vec<NetworkCommand>, Option<DownloadInfo>) {
    let mut commands = Vec::new();
    let completed = local
        .poll_chunks_at(now, |command| {
            commands.push(command);
            Ok(true)
        })
        .unwrap();
    (commands, completed)
}

fn source_connection(command: &NetworkCommand) -> [u8; 16] {
    match command {
        NetworkCommand::SendBulk { connection_id, .. } => *connection_id,
        _ => panic!("expected chunk request"),
    }
}

fn response(
    command: &NetworkCommand,
    source: &VerifiedFetchManifest,
    data: &[u8],
) -> MatchedBulkResponse {
    let NetworkCommand::SendBulk {
        connection_id,
        request,
    } = command
    else {
        panic!("expected chunk request");
    };
    assert_eq!(*connection_id, source.connection_id);
    assert_eq!(request.operation, BulkOperation::Chunk);
    assert_eq!(request.lease_id, source.lease_id);
    let offset = request.chunk_index as usize * CHUNK_SIZE as usize;
    MatchedBulkResponse {
        connection_id: *connection_id,
        agent_id: source.agent_id,
        peer_id: source.peer_id.clone(),
        request: request.clone(),
        response: BulkResponse {
            request_id: request.request_id,
            status: BulkStatus::Success,
            payload: data[offset..data.len().min(offset + CHUNK_SIZE as usize)].to_vec(),
        },
    }
}

fn deliver(local: &mut LocalDownloads, matched: MatchedBulkResponse, now: u64) {
    local
        .handle_chunk_event_at(&AdmittedNetworkEvent::BulkTransferResponse(matched), now)
        .unwrap();
}

fn assigned(home: &std::path::Path) -> u32 {
    Inbox::database(home)
        .query_row(
            "SELECT count(*) FROM transfer_chunks WHERE state='assigned'",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

#[test]
fn two_authorized_sources_can_finish_a_file_after_three_corrupt_chunks() {
    let data = [vec![1; CHUNK_SIZE as usize * 3], vec![2; 19]].concat();
    let mut inbox = Inbox::new(&data);
    let good = inbox.new_source();
    let unapproved = inbox.new_source();
    let DownloadStart::Started(info) = inbox
        .local
        .request_download_from(&[&inbox.event, &good], inbox.grant, "item.bin")
        .unwrap()
    else {
        panic!("expected download");
    };
    let bad = &inbox.event;
    let local = &mut inbox.local;
    local.resume_chunks(&info.transfer_id).unwrap();
    assert!(matches!(
        local.attach_chunk_source(&unapproved),
        Err(AslError::PolicyDenied)
    ));
    local.attach_chunk_source(bad).unwrap();
    local.attach_chunk_source(&good).unwrap();
    let now = unix_time_ms().unwrap();
    let mut durable = 0;

    for attempt in 0..3 {
        let (requests, complete) = collect(local, now + attempt);
        assert!(complete.is_none());
        let (bad_requests, good_requests): (Vec<_>, Vec<_>) = requests
            .iter()
            .partition(|command| source_connection(command) == bad.connection_id);
        assert_eq!(bad_requests.len(), 2);
        let mut corrupt = response(bad_requests[0], bad, &data);
        if attempt == 0 {
            assert_eq!(good_requests.len(), 2);
            corrupt.response.payload.pop();
        } else {
            corrupt.response.payload[0] ^= 1;
        }
        deliver(local, corrupt, now + attempt);
        assert!(collect(local, now + attempt).0.is_empty());
        deliver(local, response(bad_requests[1], bad, &data), now + attempt);
        assert_eq!(
            local.broker.info(&info.transfer_id).unwrap().durable_bytes,
            durable
        );
        for command in good_requests {
            let matched = response(command, &good, &data);
            durable += matched.response.payload.len() as u64;
            deliver(local, matched, now + attempt);
        }
        if attempt < 2 {
            local.pause_chunks().unwrap();
            local.resume_chunks(&info.transfer_id).unwrap();
            local.attach_chunk_source(bad).unwrap();
        }
    }
    assert!(matches!(
        local.attach_chunk_source(bad),
        Err(AslError::PolicyDenied)
    ));
    local.attach_chunk_source(&good).unwrap();
    let (requests, _) = collect(local, now + 3);
    assert_eq!(requests.len(), 2);
    for command in requests {
        deliver(local, response(&command, &good, &data), now + 3);
    }
    let complete = collect(local, now + 4).1.unwrap();
    assert_eq!(fs::read(complete.destination_path).unwrap(), data);
    assert!(!complete.part_path.exists());
    assert!(collect(local, now + 5).1.is_none());
}

#[test]
fn restart_only_requests_nondurable_blocks_with_a_current_lease() {
    let data = vec![7; CHUNK_SIZE as usize + 19];
    let mut inbox = Inbox::new(&data);
    let transfer = inbox.start();
    let Inbox {
        mut local,
        event,
        home,
        _temp,
        ..
    } = inbox;
    local.resume_chunks(&transfer).unwrap();
    local.attach_chunk_source(&event).unwrap();
    let now = unix_time_ms().unwrap();
    let (requests, _) = collect(&mut local, now);
    assert_eq!(requests.len(), 2);
    let first = response(&requests[0], &event, &data);
    let late = response(&requests[1], &event, &data);
    let mut mismatch = first.clone();
    mismatch.agent_id.0[0] ^= 1;
    deliver(&mut local, mismatch, now);
    assert_eq!(local.broker.info(&transfer).unwrap().durable_bytes, 0);
    deliver(&mut local, first.clone(), now);
    deliver(&mut local, first, now);
    assert_eq!(assigned(&home), 1);
    assert_eq!(
        local.broker.info(&transfer).unwrap().durable_bytes,
        u64::from(CHUNK_SIZE)
    );
    drop(local);

    let mut local = LocalDownloads::open(&AppPaths::open(&home).unwrap()).unwrap();
    assert_eq!(assigned(&home), 0);
    local.resume_chunks(&transfer).unwrap();
    assert!(collect(&mut local, now + 1).0.is_empty());
    let fresh = fresh_connection(&event);
    local.attach_chunk_source(&fresh).unwrap();
    let (requests, _) = collect(&mut local, now + 2);
    assert_eq!(requests.len(), 1);
    let tail = response(&requests[0], &fresh, &data);
    assert_eq!(tail.request.chunk_index, 1);
    assert_ne!(tail.request.request_id, late.request.request_id);
    deliver(&mut local, late, now + 2);
    assert_eq!(assigned(&home), 1);
    deliver(&mut local, tail, now + 2);
    let complete = collect(&mut local, now + 3).1.unwrap();
    assert_eq!(fs::read(complete.destination_path).unwrap(), data);
}

fn fresh_connection(source: &VerifiedFetchManifest) -> VerifiedFetchManifest {
    let mut fresh = source.clone();
    fresh.0.connection_id = rand::random();
    fresh.0.lease_id = Hash32(rand::random());
    fresh.0.fetch_generation += 1;
    fresh
}

#[test]
fn backpressure_timeout_and_disconnect_release_assignments_without_reusing_tickets() {
    let data = vec![3; CHUNK_SIZE as usize + 1];
    let mut inbox = Inbox::new(&data);
    let transfer = inbox.start();
    let local = &mut inbox.local;
    local.resume_chunks(&transfer).unwrap();
    local.attach_chunk_source(&inbox.event).unwrap();
    let now = unix_time_ms().unwrap();
    let mut attempted = 0;
    local
        .poll_chunks_at(now, |_| {
            attempted += 1;
            Ok(false)
        })
        .unwrap();
    assert_eq!(attempted, 1);
    assert_eq!(assigned(&inbox.home), 0);

    let (sent, _) = collect(local, now + 1);
    assert_eq!(assigned(&inbox.home), 2);
    let deadline = local
        .chunks
        .as_ref()
        .unwrap()
        .pending
        .values()
        .map(|pending| pending.deadline_ms)
        .min()
        .unwrap();
    assert!(collect(local, deadline).0.is_empty());
    assert_eq!(assigned(&inbox.home), 0);
    local.attach_chunk_source(&inbox.event).unwrap();
    assert!(collect(local, deadline).0.is_empty());

    let source = fresh_connection(&inbox.event);
    local.attach_chunk_source(&source).unwrap();
    assert!(matches!(
        local.attach_chunk_source(&inbox.event),
        Err(AslError::ExpiredMessage)
    ));
    let (retried, _) = collect(local, deadline + 1);
    deliver(local, response(&sent[0], &inbox.event, &data), deadline + 1);
    assert_eq!(assigned(&inbox.home), 2);
    local
        .handle_chunk_event_at(
            &AdmittedNetworkEvent::PeerDisconnected {
                connection_id: source.connection_id,
                peer_id: Some(source.peer_id.clone()),
                agent_id: Some(source.agent_id),
            },
            deadline + 1,
        )
        .unwrap();
    assert_eq!(assigned(&inbox.home), 0);

    let reconnected = fresh_connection(&source);
    local.attach_chunk_source(&reconnected).unwrap();
    let (retried_again, _) = collect(local, deadline + 2);
    let good = response(&retried_again[0], &reconnected, &data);
    deliver(local, response(&retried[0], &source, &data), deadline + 2);
    let failed = AdmittedNetworkEvent::RequestFailed {
        connection_id: good.connection_id,
        agent_id: good.agent_id,
        peer_id: good.peer_id.clone(),
        request_id: good.request.request_id.0,
        protocol: NetworkProtocol::Bulk,
        code: NetworkErrorCode::TimedOut,
    };
    local.handle_chunk_event_at(&failed, deadline + 2).unwrap();
    assert_eq!(assigned(&inbox.home), 0);
    assert!(collect(local, deadline + 2).0.is_empty());
    assert_eq!(local.broker.info(&transfer).unwrap().durable_bytes, 0);
}

#[test]
fn approval_binds_the_whole_source_set_before_scheduling() {
    let mut inbox = Inbox::new(&vec![5; CHUNK_SIZE as usize + 1]);
    let other = inbox.new_source();
    inbox
        .local
        .set_download_mode(super::super::DownloadMode::Ask)
        .unwrap();
    let DownloadStart::Pending(consent) = inbox
        .local
        .request_download_from(&[&inbox.event, &other], inbox.grant, "item.bin")
        .unwrap()
    else {
        panic!("expected local consent");
    };
    assert_eq!(fs::read_dir(&inbox.folder).unwrap().count(), 0);
    inbox.local.decide_download(consent, true).unwrap();
    assert!(
        inbox
            .local
            .begin_approved_download(&inbox.event, inbox.grant, "item.bin", consent)
            .is_err()
    );
    let info = inbox
        .local
        .begin_approved_download_from(&[&other, &inbox.event], inbox.grant, "item.bin", consent)
        .unwrap();
    assert!(inbox.local.resume_chunks(&info.transfer_id).is_ok());
}

#[test]
fn an_idle_transfer_releases_its_reservation_without_reopening_the_broker() {
    let mut inbox = Inbox::new(&vec![2; MAX_INLINE_BYTES as usize + 1]);
    let transfer = inbox.start();
    inbox.local.resume_chunks(&transfer).unwrap();
    let deadline = inbox.local.chunks.as_ref().unwrap().idle_deadline_ms;
    assert!(collect(&mut inbox.local, deadline - 1).0.is_empty());
    assert!(inbox.folder.join("item.bin.part").exists());
    assert!(collect(&mut inbox.local, deadline).0.is_empty());
    assert!(inbox.local.chunks.is_none());
    assert!(!inbox.folder.join("item.bin.part").exists());
    assert_eq!(
        Inbox::database(&inbox.home)
            .query_row("SELECT state FROM reservations", [], |row| row
                .get::<_, String>(0))
            .unwrap(),
        "released"
    );
}

#[test]
fn idle_sweep_releases_a_paused_transfer_when_no_coordinator_exists() {
    let mut inbox = Inbox::new(&vec![2; MAX_INLINE_BYTES as usize + 1]);
    let transfer = inbox.start();
    inbox.local.resume_chunks(&transfer).unwrap();
    let deadline = inbox.local.chunks.as_ref().unwrap().idle_deadline_ms;
    inbox.local.pause_chunks().unwrap();
    assert!(inbox.folder.join("item.bin.part").exists());
    assert!(collect(&mut inbox.local, deadline).0.is_empty());
    assert!(!inbox.folder.join("item.bin.part").exists());
}

#[test]
fn net_capacity_only_releases_the_unsent_request_and_keeps_its_lease() {
    let data = vec![6; CHUNK_SIZE as usize + 1];
    let mut inbox = Inbox::new(&data);
    let transfer = inbox.start();
    inbox.local.resume_chunks(&transfer).unwrap();
    inbox.local.attach_chunk_source(&inbox.event).unwrap();
    let now = unix_time_ms().unwrap();
    let (requests, _) = collect(&mut inbox.local, now);
    let unsent = response(&requests[0], &inbox.event, &data);
    let sibling = response(&requests[1], &inbox.event, &data);
    let capacity = AdmittedNetworkEvent::RequestFailed {
        connection_id: unsent.connection_id,
        agent_id: unsent.agent_id,
        peer_id: unsent.peer_id,
        request_id: unsent.request.request_id.0,
        protocol: NetworkProtocol::Bulk,
        code: NetworkErrorCode::Capacity,
    };
    inbox.local.handle_chunk_event_at(&capacity, now).unwrap();
    assert_eq!(assigned(&inbox.home), 1);
    let (retried, _) = collect(&mut inbox.local, now + 1);
    assert_eq!(retried.len(), 1);
    let retried = response(&retried[0], &inbox.event, &data);
    assert_eq!(retried.request.chunk_index, unsent.request.chunk_index);
    deliver(&mut inbox.local, sibling, now + 1);
    deliver(&mut inbox.local, retried, now + 1);
    assert!(collect(&mut inbox.local, now + 2).1.is_some());
}

#[test]
fn pausing_with_outstanding_requests_does_not_immediately_reissue_them() {
    let data = vec![1; CHUNK_SIZE as usize + 1];
    let mut inbox = Inbox::new(&data);
    let transfer = inbox.start();
    inbox.local.resume_chunks(&transfer).unwrap();
    inbox.local.attach_chunk_source(&inbox.event).unwrap();
    let now = unix_time_ms().unwrap();
    let (old, _) = collect(&mut inbox.local, now);
    inbox.local.pause_chunks().unwrap();
    assert_eq!(assigned(&inbox.home), 0);
    inbox.local.resume_chunks(&transfer).unwrap();
    inbox.local.attach_chunk_source(&inbox.event).unwrap();
    assert!(collect(&mut inbox.local, now + 1).0.is_empty());
    for command in old {
        deliver(
            &mut inbox.local,
            response(&command, &inbox.event, &data),
            now + 1,
        );
    }
    assert_eq!(inbox.local.broker.info(&transfer).unwrap().durable_bytes, 0);
    assert_eq!(collect(&mut inbox.local, now + 2).0.len(), 2);
}
