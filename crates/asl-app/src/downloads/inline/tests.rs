use std::fs;

use super::*;
use crate::downloads::test_inbox::Inbox;
use asl_net::codec::BulkResponse;
use asl_store::resources::SnapshotBroker;

impl Inbox {
    fn request(&self, task: &TransferId, bytes: &[u8]) -> (InlineDownload, MatchedBulkResponse) {
        let (ticket, cmd) = self.local.prepare_inline(task, &self.event).unwrap();
        let NetworkCommand::SendBulk {
            connection_id,
            request,
        } = cmd
        else {
            panic!("expected bulk");
        };
        assert_eq!(request.operation, BulkOperation::Inline);
        let response = BulkResponse {
            request_id: request.request_id,
            status: BulkStatus::Success,
            payload: bytes.to_vec(),
        };
        (
            ticket,
            MatchedBulkResponse {
                connection_id,
                agent_id: self.event.agent_id,
                peer_id: self.event.peer_id.clone(),
                request,
                response,
            },
        )
    }
}

#[test]
fn empty_and_maximum_inline_responses_finalize_only_their_local_request() {
    for bytes in [vec![], vec![0x51; MAX_INLINE_BYTES as usize]] {
        let mut inbox = Inbox::new(&bytes);
        let task = inbox.start();
        let (mut ticket, mut matched) = inbox.request(&task, &bytes);
        matched.connection_id[0] ^= 1;
        assert_eq!(ticket.receive(&mut inbox.local, &matched).unwrap(), None);
        matched.connection_id[0] ^= 1;
        matched.request.lease_id.0[0] ^= 1;
        assert_eq!(ticket.receive(&mut inbox.local, &matched).unwrap(), None);
        matched.request.lease_id.0[0] ^= 1;
        assert!(!inbox.folder.join("item.bin").exists());
        let info = ticket.receive(&mut inbox.local, &matched).unwrap().unwrap();
        assert_eq!(info.state, "complete");
        assert_eq!(fs::read(info.destination_path).unwrap(), bytes);
        assert!(!info.part_path.exists());
        assert_eq!(ticket.receive(&mut inbox.local, &matched).unwrap(), None);
    }
}

#[test]
fn bad_bytes_or_loss_of_authority_cannot_publish_the_destination() {
    let mut inbox = Inbox::new(b"binding");
    let task = inbox.start();
    let (mut bad, response) = inbox.request(&task, b"changed");
    assert!(matches!(
        bad.receive(&mut inbox.local, &response),
        Err(AslError::InvalidMessage)
    ));
    assert_eq!(bad.receive(&mut inbox.local, &response).unwrap(), None);
    let (mut expired, good) = inbox.request(&task, b"binding");
    expired.expires_at_ms = unix_time_ms().unwrap();
    assert!(matches!(
        expired.receive(&mut inbox.local, &good),
        Err(AslError::ExpiredMessage)
    ));
    let (mut revoked, good) = inbox.request(&task, b"binding");
    SnapshotBroker::open(&inbox.home)
        .unwrap()
        .revoke_inbox_directory(inbox.grant)
        .unwrap();
    assert!(revoked.receive(&mut inbox.local, &good).is_err());
    assert!(!inbox.folder.join("item.bin").exists());
    assert_eq!(inbox.local.broker.info(&task).unwrap().durable_bytes, 0);
}

#[test]
fn larger_files_cannot_use_the_inline_channel() {
    let mut inbox = Inbox::new(&vec![7; MAX_INLINE_BYTES as usize + 1]);
    let task = inbox.start();
    assert!(matches!(
        inbox.local.prepare_inline(&task, &inbox.event),
        Err(AslError::QuotaExceeded)
    ));
}
