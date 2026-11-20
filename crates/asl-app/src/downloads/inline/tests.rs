use std::{fs, path::PathBuf};

use super::*;
use crate::{
    FetchManifestDetails,
    downloads::DownloadStart,
    identity::{AgentIdentity, DeviceIdentity},
    paths::AppPaths,
    transfer::tests::Fixture,
};
use asl_net::codec::BulkResponse;
use asl_store::resources::SnapshotBroker;
use asl_types::{
    ids::Hash32,
    manifest::{Manifest, content_id, encode_manifest},
};
use rusqlite::{Connection, params};

struct Inbox {
    local: LocalDownloads,
    event: VerifiedFetchManifest,
    home: PathBuf,
    folder: PathBuf,
    grant: Id128,
    _temp: Fixture,
}

impl Inbox {
    fn new(bytes: &[u8]) -> Self {
        let temp = Fixture::new();
        let home = temp.path().join("home");
        let folder = temp.path().join("inbox");
        fs::create_dir(&folder).unwrap();
        let paths = AppPaths::open(&home).unwrap();
        let grant = SnapshotBroker::open(&home)
            .unwrap()
            .authorize_inbox_directory(&folder, 1 << 20)
            .unwrap();
        let local = LocalDownloads::open(&paths).unwrap();
        let now = unix_time_ms().unwrap();
        let identity = AgentIdentity::generate().unwrap();
        let device = DeviceIdentity::generate().unwrap();
        let peer = device.peer_id();
        let cert = identity
            .issue_device_certificate(peer.clone(), 1, now - 1, now + 60_000)
            .unwrap();
        let db = Connection::open(paths.state().join("asl.sqlite3")).unwrap();
        let agent = bs58::encode(identity.agent_id().0).into_string();
        let key = device.into_keypair().public().try_into_ed25519().unwrap();
        let peer_text = bs58::encode(peer.as_bytes()).into_string();
        // Identity admission/manifest routing has a separate production-path test.
        // This fixture starts with its already registered, genuinely signed device.
        db.execute("INSERT INTO agents(agent_id) VALUES (?1)", [&agent])
            .unwrap();
        db.execute(
            "INSERT INTO device_identities(peer_id,agent_id,public_key_hex,certificate_cbor,
          certificate_serial,certificate_expires_ms,created_at_ms) VALUES (?1,?2,?3,?4,1,?5,?6)",
            params![
                peer_text,
                agent,
                alloy_primitives::hex::encode(key.to_bytes()),
                cert.to_canonical_cbor().unwrap(),
                cert.expires_at_ms as i64,
                now as i64
            ],
        )
        .unwrap();
        db.execute(
            "INSERT INTO peers(peer_id,agent_id) VALUES (?1,?2)",
            params![peer_text, agent],
        )
        .unwrap();
        let hash = *blake3::hash(bytes).as_bytes();
        let manifest = Manifest {
            file_size: bytes.len() as u64,
            file_hash: hash,
            chunk_hashes: if bytes.is_empty() { vec![] } else { vec![hash] },
        };
        let event = VerifiedFetchManifest(FetchManifestDetails {
            fetch_request_id: Id128([1; 16]),
            root_task_id: Id128([2; 16]),
            connection_id: [3; 16],
            agent_id: identity.agent_id(),
            peer_id: peer,
            content_id: Hash32(content_id(&encode_manifest(&manifest).unwrap())),
            lease_id: Hash32([4; 32]),
            expires_at_ms: now + 60_000,
            manifest,
        });
        Self {
            local,
            event,
            home,
            folder,
            grant,
            _temp: temp,
        }
    }

    fn start(&mut self) -> TransferId {
        let DownloadStart::Started(info) = self
            .local
            .request_download(&self.event, self.grant, "item.bin")
            .unwrap()
        else {
            panic!("expected an authorized download");
        };
        info.transfer_id
    }

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
