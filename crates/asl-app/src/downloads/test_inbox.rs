use std::{fs, path::PathBuf};

use asl_store::resources::SnapshotBroker;
use asl_types::{
    ids::{Hash32, Id128},
    manifest::{CHUNK_SIZE, Manifest, content_id, encode_manifest},
    task::TransferId,
};
use rusqlite::{Connection, params};

use super::{DownloadStart, LocalDownloads};
use crate::{
    FetchManifestDetails, VerifiedFetchManifest,
    identity::{AgentIdentity, DeviceIdentity},
    paths::AppPaths,
    supervisor::unix_time_ms,
    transfer::tests::Fixture,
};

pub(super) struct Inbox {
    pub local: LocalDownloads,
    pub event: VerifiedFetchManifest,
    pub home: PathBuf,
    pub folder: PathBuf,
    pub grant: Id128,
    pub _temp: Fixture,
}

impl Inbox {
    pub fn new(bytes: &[u8]) -> Self {
        let temp = Fixture::new();
        let home = temp.path().join("home");
        let folder = temp.path().join("inbox");
        fs::create_dir(&folder).unwrap();
        let paths = AppPaths::open(&home).unwrap();
        let grant = SnapshotBroker::open(&home)
            .unwrap()
            .authorize_inbox_directory(&folder, 8 << 20)
            .unwrap();
        let local = LocalDownloads::open(&paths).unwrap();
        let manifest = Manifest {
            file_size: bytes.len() as u64,
            file_hash: *blake3::hash(bytes).as_bytes(),
            chunk_hashes: bytes
                .chunks(CHUNK_SIZE as usize)
                .map(|chunk| *blake3::hash(chunk).as_bytes())
                .collect(),
        };
        let event = Self::register_source(&home, manifest);
        Self {
            local,
            event,
            home,
            folder,
            grant,
            _temp: temp,
        }
    }

    pub fn database(home: &std::path::Path) -> Connection {
        Connection::open(home.join("state").join("asl.sqlite3")).unwrap()
    }

    pub fn new_source(&self) -> VerifiedFetchManifest {
        Self::register_source(&self.home, self.event.manifest.clone())
    }

    fn register_source(home: &std::path::Path, manifest: Manifest) -> VerifiedFetchManifest {
        let now = unix_time_ms().unwrap();
        let identity = AgentIdentity::generate().unwrap();
        let device = DeviceIdentity::generate().unwrap();
        let peer = device.peer_id();
        let cert = identity
            .issue_device_certificate(peer.clone(), 1, now - 1, now + 60_000)
            .unwrap();
        let db = Self::database(home);
        let agent = bs58::encode(identity.agent_id().0).into_string();
        let key = device.into_keypair().public().try_into_ed25519().unwrap();
        let peer_text = bs58::encode(peer.as_bytes()).into_string();
        // Admission is covered separately. Use registered, signed devices
        // here so the broker's identity and inbox checks run against real state.
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
        VerifiedFetchManifest(FetchManifestDetails {
            fetch_generation: 1,
            fetch_request_id: Id128(rand::random()),
            root_task_id: Id128(rand::random()),
            connection_id: rand::random(),
            agent_id: identity.agent_id(),
            peer_id: peer,
            content_id: Hash32(content_id(&encode_manifest(&manifest).unwrap())),
            lease_id: Hash32(rand::random()),
            expires_at_ms: now + 60_000,
            manifest,
        })
    }

    pub fn start(&mut self) -> TransferId {
        let DownloadStart::Started(info) = self
            .local
            .request_download(&self.event, self.grant, "item.bin")
            .unwrap()
        else {
            panic!("expected an authorized download");
        };
        info.transfer_id
    }
}
