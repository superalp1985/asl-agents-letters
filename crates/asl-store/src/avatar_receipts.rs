//! Receiver-only state for explicitly reviewed profile avatars.

use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128},
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::{
    Store, avatar_publication::MAX_IMAGE_BYTES, chain::agent_text, current_time_ms,
    dashboard::read_identity, database_error, network_privacy::network_pause_requested,
    remote_profiles::VISIBLE,
};

const REQUEST_WINDOW_MS: i64 = 60_000;
const SAME_PROFILE: &str = "AND p.agent_id=a.owner AND p.agent_key=a.owner_key
    AND p.avatar_content_id=a.content_id AND p.chain_id=a.chain_id
    AND p.checkpoint_hash=a.checkpoint_hash AND p.registry_sequence=a.registry_sequence
    AND p.profile_sequence=a.profile_sequence";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AvatarDownload {
    pub id: Id128,
    pub owner: AgentId,
    pub content: Hash32,
    pub expires_at_ms: u64,
}

impl Store {
    /// Queue the exact reference that a local operator reviewed. Repeating
    /// the same live request does not extend its deadline.
    pub fn request_avatar_download(
        &mut self,
        owner: AgentId,
        content: Hash32,
    ) -> Result<(), AslError> {
        let tx = immediate(&self.connection)?;
        let now = current_time_ms();
        if network_pause_requested(&tx)? {
            return Err(AslError::PolicyDenied);
        }
        let local = local_agent(&tx)?.ok_or(AslError::InvalidIdentity)?;
        let owner_text = agent_text(owner);
        if local == owner_text {
            return Err(AslError::PolicyDenied);
        }
        if let Some(request) = pending(&tx, now, &local)? {
            return if request.owner == owner && request.content == content {
                Ok(())
            } else {
                Err(AslError::QuotaExceeded)
            };
        }
        tx.execute(
            "DELETE FROM avatar_receipts WHERE image IS NULL OR expires_at_ms<=?1",
            [now],
        )
        .map_err(database_error)?;
        let inserted = tx
            .prepare_cached(&format!(
                "INSERT INTO avatar_receipts(
                    owner,owner_key,local_agent_id,content_id,chain_id,checkpoint_hash,
                    registry_sequence,profile_sequence,request_id,requested_at_ms,expires_at_ms)
                 SELECT p.agent_id,p.agent_key,?2,p.avatar_content_id,p.chain_id,p.checkpoint_hash,
                    p.registry_sequence,p.profile_sequence,randomblob(16),?1,min(?3,p.expires_at_ms)
                 {VISIBLE} AND p.agent_id=?4 AND p.agent_key=?5 AND p.avatar_content_id=?6
                 ON CONFLICT(owner) DO NOTHING"
            ))
            .map_err(database_error)?
            .execute(params![
                now,
                local,
                now.saturating_add(REQUEST_WINDOW_MS),
                owner_text,
                owner.as_bytes(),
                content.as_bytes(),
            ])
            .map_err(database_error)?;
        if inserted == 0 && read_image(&tx, now, &local, owner, content)?.is_none() {
            return Err(AslError::NotFound);
        }
        tx.commit().map_err(database_error)
    }

    pub fn pending_avatar_download(&self, now_ms: u64) -> Result<Option<AvatarDownload>, AslError> {
        let tx = self
            .connection
            .unchecked_transaction()
            .map_err(database_error)?;
        // The idle Core only probes the one-pending-row index.
        let exists: bool = tx
            .prepare_cached("SELECT EXISTS(SELECT 1 FROM avatar_receipts WHERE image IS NULL)")
            .map_err(database_error)?
            .query_row([], |row| row.get(0))
            .map_err(database_error)?;
        if !exists {
            return Ok(None);
        }
        current_request(&tx, sql_time(now_ms)?)
    }

    /// Serialize only the nonblocking enqueue with cancellation, pause, and
    /// identity/profile changes. The caller must check live peer admission.
    pub fn with_avatar_download(
        &mut self,
        req: &AvatarDownload,
        now: u64,
        enqueue: impl FnOnce() -> Result<bool, AslError>,
    ) -> Result<bool, AslError> {
        let tx = immediate(&self.connection)?;
        if current_request(&tx, sql_time(now)?.max(current_time_ms()))?.as_ref() != Some(req) {
            return Ok(false);
        }
        enqueue()
    }

    /// Only Core may pass bytes here, after checking the admitted sender,
    /// verifying the original content ID, and re-encoding in the Extractor.
    /// The sanitized bytes can have a different content ID from the original.
    pub fn finish_avatar_download(
        &mut self,
        request: &AvatarDownload,
        sanitized: Option<&[u8]>,
        now_ms: u64,
    ) -> Result<bool, AslError> {
        let tx = immediate(&self.connection)?;
        let expires = sql_time(request.expires_at_ms)?;
        let Some(image) = sanitized else {
            let changed = tx
                .execute(
                    "DELETE FROM avatar_receipts WHERE image IS NULL AND request_id=?1
                     AND owner_key=?2 AND content_id=?3 AND expires_at_ms=?4",
                    params![
                        &request.id.0,
                        request.owner.as_bytes(),
                        request.content.as_bytes(),
                        expires
                    ],
                )
                .map_err(database_error)?;
            tx.commit().map_err(database_error)?;
            return Ok(changed == 1);
        };
        if current_request(&tx, sql_time(now_ms)?.max(current_time_ms()))?.as_ref() != Some(request)
        {
            return Ok(false);
        }
        if image.len() > MAX_IMAGE_BYTES
            || !(image.starts_with(b"\x89PNG\r\n\x1a\n")
                || (image.starts_with(b"RIFF") && image.get(8..12) == Some(&b"WEBP"[..])))
        {
            return Err(AslError::InvalidMessage);
        }
        let changed = tx
            .execute(
                "UPDATE avatar_receipts SET image=?2,expires_at_ms=(
                    SELECT p.expires_at_ms FROM observed_remote_profiles p
                    WHERE p.agent_id=avatar_receipts.owner
                 ) WHERE request_id=?1 AND image IS NULL",
                params![&request.id.0, image],
            )
            .map_err(database_error)?;
        tx.commit().map_err(database_error)?;
        Ok(changed == 1)
    }

    pub fn received_avatar(
        &self,
        owner: AgentId,
        content: Hash32,
    ) -> Result<Option<Vec<u8>>, AslError> {
        let tx = self
            .connection
            .unchecked_transaction()
            .map_err(database_error)?;
        let Some(local) = local_agent(&tx)? else {
            return Ok(None);
        };
        read_image(&tx, current_time_ms(), &local, owner, content)
    }

    pub fn cancel_avatar_download(&mut self) -> Result<(), AslError> {
        self.connection
            .execute("DELETE FROM avatar_receipts WHERE image IS NULL", [])
            .map_err(database_error)?;
        Ok(())
    }
}

fn immediate(db: &Connection) -> Result<Transaction<'_>, AslError> {
    Transaction::new_unchecked(db, TransactionBehavior::Immediate).map_err(database_error)
}

fn local_agent(db: &Connection) -> Result<Option<String>, AslError> {
    let agent = read_identity(db)?.agent_id;
    agent
        .map(|text| {
            let mut bytes = [0; 32];
            if bs58::decode(&text).onto(&mut bytes[..]).ok() == Some(bytes.len()) {
                Ok(text)
            } else {
                Err(AslError::InvalidIdentity)
            }
        })
        .transpose()
}

fn sql_time(now: u64) -> Result<i64, AslError> {
    i64::try_from(now).map_err(|_| AslError::InvalidMessage)
}

fn current_request(db: &Connection, now: i64) -> Result<Option<AvatarDownload>, AslError> {
    if network_pause_requested(db)? {
        return Ok(None);
    }
    let Some(local) = local_agent(db)? else {
        return Ok(None);
    };
    pending(db, now, &local)
}

fn pending(db: &Connection, now: i64, local: &str) -> Result<Option<AvatarDownload>, AslError> {
    db.prepare_cached(&format!(
        "SELECT a.request_id,a.owner_key,a.content_id,a.expires_at_ms FROM avatar_receipts a
         WHERE a.image IS NULL AND a.requested_at_ms<=?1 AND ?1<a.expires_at_ms
           AND a.local_agent_id=?2 AND a.owner<>?2
           AND EXISTS(SELECT 1 {VISIBLE} {SAME_PROFILE})"
    ))
    .map_err(database_error)?
    .query_row(params![now, local], |row| {
        Ok(AvatarDownload {
            id: Id128(row.get(0)?),
            owner: AgentId(row.get(1)?),
            content: Hash32(row.get(2)?),
            expires_at_ms: crate::dashboard::unsigned(3, row.get(3)?)?,
        })
    })
    .optional()
    .map_err(database_error)
}

fn read_image(
    db: &Connection,
    now: i64,
    local: &str,
    owner: AgentId,
    content: Hash32,
) -> Result<Option<Vec<u8>>, AslError> {
    db.prepare_cached(&format!(
        "SELECT a.image FROM avatar_receipts a
         WHERE a.image IS NOT NULL AND a.requested_at_ms<=?1 AND ?1<a.expires_at_ms
           AND a.local_agent_id=?2 AND a.owner=?3 AND a.owner<>?2 AND a.content_id=?4
           AND EXISTS(SELECT 1 {VISIBLE} {SAME_PROFILE})"
    ))
    .map_err(database_error)?
    .query_row(
        params![now, local, agent_text(owner), content.as_bytes()],
        |row| row.get(0),
    )
    .optional()
    .map_err(database_error)
}

#[cfg(test)]
pub(crate) fn remove_schema_for_legacy_fixture(store: &Store) {
    store
        .connection
        .execute_batch(
            "DROP TABLE mcp_recovery_download_decisions;
         DROP TABLE mcp_recovery_downloads;
         DROP TABLE mcp_recovery_events;
         DROP TABLE mcp_recovery_tasks;
         DROP TABLE mcp_recovery_grant;
         DELETE FROM schema_migrations WHERE version IN (28,29,30,31,32);
         DROP TABLE received_file_retention;
         ALTER TABLE write_grants DROP COLUMN inbox_retention_days;
         DELETE FROM schema_migrations WHERE version=27;
         DROP TRIGGER avatar_receipts_profile_changed;
         DROP TRIGGER avatar_receipts_registry_changed;
         DROP TRIGGER avatar_receipts_registry_removed;
         DROP TRIGGER avatar_receipts_checkpoint_changed;
         DROP TRIGGER avatar_receipts_block_insert;
         DROP TRIGGER avatar_receipts_block_update;
         DROP TRIGGER avatar_receipts_settings_insert;
         DROP TRIGGER avatar_receipts_settings_update;
         DROP TRIGGER avatar_receipts_settings_delete;
         DROP TRIGGER avatar_receipts_local_insert;
         DROP TRIGGER avatar_receipts_local_update;
         DROP TRIGGER avatar_receipts_local_delete;
         DROP TABLE avatar_receipts;
         DROP TABLE mls_shard_forward_receipts;
         DROP TABLE mls_shard_bindings;
         DROP TABLE mls_room_shards;
         DROP TABLE group_removal_requests;
         DROP TABLE conversation_act_semantic_index;
         DROP TABLE conversation_attachment_refs;
         DROP TABLE conversation_act_events;
         DROP TABLE conversation_budget_grants;
         DROP TABLE mailbox_shards;
         DROP TABLE mailbox_slots;
         DROP TABLE gossip_topic_state;
         DROP TABLE local_capacity_measurements;
         DROP TABLE semantic_context_resources;
         DROP TABLE semantic_context_candidates;
         DROP TABLE group_admin_capabilities;
         DROP TABLE group_file_policies;
         DROP TABLE group_access_members;
         DROP TABLE group_access_policies;
         DROP TABLE group_invite_requests;
         DROP TABLE migration_group_hints;
         DROP TABLE resource_budget_grants;
         DROP TABLE IF EXISTS dht_provider_cache_v42;
         DROP TABLE dht_provider_cache;
         DROP TABLE dht_record_cache;
         DELETE FROM schema_migrations WHERE version>=33;",
        )
        .unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{dashboard::LocalIdentityProjection, open_store, open_store_read_only};
    use asl_types::protocol::Profile;

    const LOCAL: AgentId = AgentId([1; 32]);
    const OWNER: AgentId = AgentId([2; 32]);
    const OTHER: AgentId = AgentId([3; 32]);
    const CONTENT: Hash32 = Hash32([4; 32]);
    const WRONG: Hash32 = Hash32([5; 32]);

    struct Fixture {
        dir: tempfile::TempDir,
        store: Store,
        issued: u64,
        expires: u64,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let store = open_store(&dir.path().join("store.sqlite3")).unwrap();
            store
                .connection
                .execute_batch(
                    "INSERT INTO chain_state_cache VALUES
                 (1,zeroblob(20),zeroblob(32),1,zeroblob(32),zeroblob(32),zeroblob(32),x'',0);",
                )
                .unwrap();
            for owner in [OWNER, OTHER] {
                let owner = agent_text(owner);
                store
                    .connection
                    .execute("INSERT INTO agents(agent_id) VALUES (?1)", [&owner])
                    .unwrap();
                store
                    .connection
                    .execute(
                        "INSERT INTO identity_registry_states VALUES
                     (?1,1,zeroblob(20),zeroblob(32),7,'active',1,zeroblob(32),0)",
                        [&owner],
                    )
                    .unwrap();
            }
            set_local(&store, LOCAL);
            let issued = current_time_ms() as u64;
            Self {
                dir,
                store,
                issued,
                expires: issued + 45_000,
            }
        }

        fn other_connection(&self) -> Store {
            open_store(&self.dir.path().join("store.sqlite3")).unwrap()
        }

        fn observe(&mut self, owner: AgentId, sequence: u64, avatar: Option<Hash32>) {
            self.store
                .observe_remote_profile(
                    &Profile {
                        agent_id: owner,
                        sequence,
                        capabilities: vec![],
                        avatar,
                    },
                    7,
                    self.issued,
                    self.expires,
                    self.issued,
                )
                .unwrap();
        }

        fn request(&mut self) -> AvatarDownload {
            self.store.request_avatar_download(OWNER, CONTENT).unwrap();
            self.store
                .pending_avatar_download(current_time_ms() as u64)
                .unwrap()
                .unwrap()
        }
    }

    fn set_local(store: &Store, agent: AgentId) {
        store
            .set_local_identity_projection(&LocalIdentityProjection {
                agent_id: agent_text(agent),
                peer_id: String::new(),
                network_state: "network_active".into(),
                binding_code: String::new(),
            })
            .unwrap();
    }

    fn png() -> Vec<u8> {
        hex::decode(concat!(
            "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489",
            "0000000d49444154789c63606165fb0f00012f010f953177610000000049454e44ae426082"
        ))
        .unwrap()
    }

    #[test]
    fn only_an_explicit_exact_visible_avatar_can_take_the_global_slot() {
        let mut f = Fixture::new();
        f.observe(OWNER, 1, Some(CONTENT));
        f.observe(OTHER, 1, Some(CONTENT));
        let now = || current_time_ms() as u64;
        assert!(f.store.pending_avatar_download(now()).unwrap().is_none());
        assert!(matches!(
            f.store.request_avatar_download(OWNER, WRONG),
            Err(AslError::NotFound)
        ));
        assert!(matches!(
            f.store.request_avatar_download(LOCAL, CONTENT),
            Err(AslError::PolicyDenied)
        ));
        let request = f.request();
        assert_eq!(request.expires_at_ms, f.expires);
        let mut cli = f.other_connection();
        assert_eq!(f.request(), request);
        assert!(matches!(
            cli.request_avatar_download(OTHER, CONTENT),
            Err(AslError::QuotaExceeded)
        ));
        assert!(
            cli.pending_avatar_download(request.expires_at_ms)
                .unwrap()
                .is_none()
        );
        assert!(
            !cli.with_avatar_download(&request, request.expires_at_ms, || panic!(
                "expired enqueue"
            ))
            .unwrap()
        );
        let wrong = AvatarDownload {
            owner: OTHER,
            ..request.clone()
        };
        assert!(!cli.finish_avatar_download(&wrong, None, now()).unwrap());
        assert!(cli.finish_avatar_download(&request, None, now()).unwrap());
        assert!(f.store.pending_avatar_download(now()).unwrap().is_none());
    }

    #[test]
    fn handoff_serializes_cancel_and_pause_does_not_resume_old_requests() {
        let mut f = Fixture::new();
        f.observe(OWNER, 1, Some(CONTENT));
        let now = || current_time_ms() as u64;
        let request = f.request();
        let mut cli = f.other_connection();
        cli.connection
            .busy_timeout(std::time::Duration::ZERO)
            .unwrap();
        assert!(
            f.store
                .with_avatar_download(&request, now(), || {
                    assert!(cli.cancel_avatar_download().is_err());
                    Ok(true)
                })
                .unwrap()
        );
        cli.cancel_avatar_download().unwrap();
        assert!(
            !f.store
                .with_avatar_download(&request, now(), || panic!("cancelled enqueue"))
                .unwrap()
        );
        let paused = f.request();
        cli.set_network_pause_requested(true).unwrap();
        assert!(matches!(
            cli.request_avatar_download(OWNER, CONTENT),
            Err(AslError::PolicyDenied)
        ));
        assert!(
            !f.store
                .with_avatar_download(&paused, now(), || panic!("paused enqueue"))
                .unwrap()
        );
        cli.set_network_pause_requested(false).unwrap();
        assert!(f.store.pending_avatar_download(now()).unwrap().is_none());
        let changed = f.request();
        set_local(&cli, AgentId([7; 32]));
        set_local(&cli, LOCAL);
        let current = f.request();
        assert_ne!(changed.id, current.id);
        assert!(
            !f.store
                .finish_avatar_download(&changed, Some(&png()), now())
                .unwrap()
        );
        assert!(
            !f.store
                .finish_avatar_download(&changed, None, now())
                .unwrap()
        );
        assert_eq!(
            f.store.pending_avatar_download(now()).unwrap(),
            Some(current)
        );
    }

    #[test]
    fn receipt_is_local_bounded_and_dies_on_a_new_generation_even_with_same_hash() {
        let mut f = Fixture::new();
        f.observe(OWNER, 1, Some(CONTENT));
        let request = f.request();
        let now = || current_time_ms() as u64;
        let image = png();
        let mut oversized = image.clone();
        oversized.resize(MAX_IMAGE_BYTES + 1, 0);
        for invalid in [b"not an image".as_slice(), &oversized] {
            assert!(matches!(
                f.store
                    .finish_avatar_download(&request, Some(invalid), now()),
                Err(AslError::InvalidMessage)
            ));
        }
        assert!(
            f.store
                .finish_avatar_download(&request, Some(&image), now())
                .unwrap()
        );
        assert!(
            !f.store
                .finish_avatar_download(&request, None, now())
                .unwrap()
        );
        assert!(f.store.pending_avatar_download(now()).unwrap().is_none());
        let read_only = open_store_read_only(&f.dir.path().join("store.sqlite3")).unwrap();
        assert_eq!(
            read_only.received_avatar(OWNER, CONTENT).unwrap(),
            Some(image)
        );
        assert!(read_only.received_avatar(OTHER, CONTENT).unwrap().is_none());
        assert!(read_only.received_avatar(OWNER, WRONG).unwrap().is_none());
        assert!(
            read_image(
                &f.store.connection,
                f.expires as i64,
                &agent_text(LOCAL),
                OWNER,
                CONTENT
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(f.store.connection.query_row(
            "SELECT (SELECT count(*) FROM grants)+(SELECT count(*) FROM resources)+(SELECT count(*) FROM snapshots)",
            [], |row| row.get::<_, i64>(0)).unwrap(), 0);
        f.observe(OWNER, 2, Some(CONTENT));
        assert!(read_only.received_avatar(OWNER, CONTENT).unwrap().is_none());
        assert!(f.store.pending_avatar_download(now()).unwrap().is_none());
        assert_ne!(f.request().id, request.id);
        f.observe(OWNER, 3, None);
        assert!(f.store.pending_avatar_download(now()).unwrap().is_none());
    }

    #[test]
    fn old_receipts_do_not_return_after_a_block_or_chain_change_is_lifted() {
        for change in ["block", "checkpoint", "registry"] {
            let mut f = Fixture::new();
            f.observe(OWNER, 1, Some(CONTENT));
            let request = f.request();
            let now = current_time_ms() as u64;
            assert!(
                f.store
                    .finish_avatar_download(&request, Some(&png()), now)
                    .unwrap()
            );
            match change {
                "block" => {
                    f.store
                        .connection
                        .execute(
                            "INSERT INTO contact_bindings VALUES (?1,'fixture','bound',0)",
                            [OWNER.as_bytes()],
                        )
                        .unwrap();
                    f.store.revoke_contact_binding(OWNER, now).unwrap();
                    assert!(f.store.received_avatar(OWNER, CONTENT).unwrap().is_none());
                    f.store.forget_contact_binding(OWNER).unwrap();
                }
                "checkpoint" => f
                    .store
                    .connection
                    .execute_batch(
                        "UPDATE chain_state_cache SET checkpoint_hash=randomblob(32);
                     UPDATE chain_state_cache SET checkpoint_hash=zeroblob(32);",
                    )
                    .unwrap(),
                "registry" => f
                    .store
                    .connection
                    .execute_batch(
                        "UPDATE identity_registry_states SET sequence=8;
                     UPDATE identity_registry_states SET sequence=7;",
                    )
                    .unwrap(),
                _ => unreachable!(),
            }
            assert!(
                f.store.received_avatar(OWNER, CONTENT).unwrap().is_none(),
                "{change}"
            );
            assert_ne!(f.request().id, request.id);
        }
    }

    #[test]
    fn upgrading_v25_preserves_visible_references_without_queuing_or_caching_images() {
        let mut f = Fixture::new();
        f.observe(OWNER, 1, Some(CONTENT));
        remove_schema_for_legacy_fixture(&f.store);
        f.store
            .connection
            .execute("DELETE FROM schema_migrations WHERE version=26", [])
            .unwrap();
        let path = f.dir.path().join("store.sqlite3");
        drop(f.store);
        let upgraded = open_store(&path).unwrap();
        assert_eq!(upgraded.schema_version(), crate::SCHEMA_VERSION as u32);
        let visible = upgraded.visible_remote_profiles().unwrap();
        assert_eq!(visible[0].avatar_content_id, Some(hex::encode(CONTENT.0)));
        assert!(
            upgraded
                .pending_avatar_download(current_time_ms() as u64)
                .unwrap()
                .is_none()
        );
        assert!(upgraded.received_avatar(OWNER, CONTENT).unwrap().is_none());
    }
}
