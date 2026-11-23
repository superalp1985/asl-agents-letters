//! Consent to reference one sanitized image; never a directory grant.

use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128},
    manifest::{Manifest, content_id, encode_manifest},
    task::{GrantId, ResourceKey},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use crate::{
    Store, database_error,
    public_profile::{approve_profile_avatar, avatar_changed},
    read_setting,
};

const LEGACY_SETTING: &str = "ui.local_avatar_v1";
pub const MAX_IMAGE_BYTES: usize = 65_536;
const SANITIZER_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AvatarGrant {
    pub agent_id: AgentId,
    pub grant_id: GrantId,
    pub resource_key: ResourceKey,
    pub epoch: u64,
    pub content_id: Hash32,
    pub sanitizer_version: u32,
}

pub struct AvatarReview {
    pub bytes: Vec<u8>,
    pub token: Option<String>,
    pub approved: bool,
}

struct Selection {
    generation: [u8; 16],
    version: u32,
    bytes: Vec<u8>,
}

impl Selection {
    fn token(&self, agent: AgentId) -> String {
        let mut digest = blake3::Hasher::new_derive_key("ASL local avatar review v1");
        digest.update(agent.as_bytes());
        digest.update(&self.generation);
        digest.update(&self.version.to_be_bytes());
        digest.update(&self.bytes);
        digest.finalize().to_hex().to_string()
    }
}

fn selection(db: &Connection) -> Result<Option<Selection>, AslError> {
    db.query_row(
        "SELECT generation,sanitizer_version,image FROM local_avatar_selection WHERE singleton=1",
        [],
        |row| {
            Ok(Selection {
                generation: row.get(0)?,
                version: row.get(1)?,
                bytes: row.get(2)?,
            })
        },
    )
    .optional()
    .map_err(database_error)
}

pub(crate) fn current_grant(
    db: &Connection,
    agent: AgentId,
) -> Result<Option<AvatarGrant>, AslError> {
    db.query_row(
        "SELECT grant_id,resource_key,epoch,content_id,sanitizer_version FROM avatar_reference_grant
         JOIN local_avatar_selection USING(singleton) WHERE agent_id=?1 AND sanitizer_version=?2",
        params![agent.as_bytes(), SANITIZER_VERSION],
        |row| Ok(AvatarGrant {
            agent_id: agent, grant_id: GrantId(Id128(row.get(0)?)),
            resource_key: ResourceKey(Id128(row.get(1)?)), epoch: crate::dashboard::unsigned(2, row.get(2)?)?,
            content_id: Hash32(row.get(3)?), sanitizer_version: row.get(4)?,
        }),
    ).optional().map_err(database_error)
}

fn clear_grant(db: &Connection) -> Result<(), AslError> {
    let owner: Option<[u8; 32]> = db
        .query_row(
            "DELETE FROM avatar_reference_grant WHERE singleton=1 RETURNING agent_id",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(database_error)?;
    if let Some(owner) = owner {
        avatar_changed(db, AgentId(owner))?;
    }
    Ok(())
}

impl Store {
    /// Only the local Extractor selection path writes bytes through this API.
    pub fn replace_sanitized_avatar(&mut self, bytes: Option<&[u8]>) -> Result<(), AslError> {
        if bytes.is_some_and(|b| b.is_empty() || b.len() > MAX_IMAGE_BYTES) {
            return Err(AslError::InvalidMessage);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        clear_grant(&tx)?;
        tx.execute("DELETE FROM local_avatar_selection WHERE singleton=1", [])
            .map_err(database_error)?;
        tx.execute("DELETE FROM settings WHERE key=?1", [LEGACY_SETTING])
            .map_err(database_error)?;
        if let Some(bytes) = bytes {
            tx.execute(
                "INSERT INTO local_avatar_selection(singleton,generation,sanitizer_version,image)
                 VALUES(1,randomblob(16),?1,?2)",
                params![SANITIZER_VERSION, bytes],
            )
            .map_err(database_error)?;
        }
        tx.commit().map_err(database_error)
    }

    /// A read-only projection never opens the root key. Approve verifies the
    /// real protected identity before comparing the reviewed token.
    pub fn avatar_review(&mut self) -> Result<Option<AvatarReview>, AslError> {
        let tx = self.connection.transaction().map_err(database_error)?;
        if let Some(selected) = selection(&tx)? {
            let agent = crate::dashboard::read_identity(&tx)?
                .agent_id
                .and_then(|id| bs58::decode(id).into_vec().ok()?.try_into().ok())
                .map(AgentId);
            let agent = agent.filter(|_| selected.version == SANITIZER_VERSION);
            let approved = match agent {
                Some(agent) => current_grant(&tx, agent)?.is_some(),
                None => false,
            };
            return Ok(Some(AvatarReview {
                token: agent.map(|a| selected.token(a)),
                bytes: selected.bytes,
                approved,
            }));
        }
        let Some(legacy) = read_setting(&tx, LEGACY_SETTING)? else {
            return Ok(None);
        };
        if legacy.len() > MAX_IMAGE_BYTES * 2 + 2 {
            return Err(AslError::InvalidDatabase);
        }
        let encoded: &str = serde_json::from_str(&legacy).map_err(|_| AslError::InvalidDatabase)?;
        Ok(Some(AvatarReview {
            bytes: hex::decode(encoded).map_err(|_| AslError::InvalidDatabase)?,
            token: None,
            approved: false,
        }))
    }

    pub fn approve_avatar_reference(
        &mut self,
        owner: AgentId,
        reviewed: &str,
    ) -> Result<(), AslError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let selected = selection(&tx)?.ok_or(AslError::PolicyVersionConflict)?;
        if selected.version != SANITIZER_VERSION || selected.token(owner) != reviewed {
            return Err(AslError::PolicyVersionConflict);
        }
        if current_grant(&tx, owner)?.is_some() {
            return Ok(());
        }
        let manifest =
            Manifest::from_bytes(&selected.bytes).map_err(|_| AslError::InvalidDatabase)?;
        let encoded = encode_manifest(&manifest).map_err(|_| AslError::InvalidDatabase)?;
        clear_grant(&tx)?;
        tx.execute(
            "INSERT INTO avatar_reference_grant(singleton,agent_id,grant_id,resource_key,epoch,content_id)
             VALUES(1,?1,randomblob(16),randomblob(16),1,?2)",
            params![owner.as_bytes(), content_id(&encoded)],
        ).map_err(database_error)?;
        let grant = current_grant(&tx, owner)?.ok_or(AslError::InvalidDatabase)?;
        approve_profile_avatar(&tx, &grant)?;
        tx.commit().map_err(database_error)
    }

    pub fn withdraw_avatar_reference(&mut self) -> Result<(), AslError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        clear_grant(&tx)?;
        tx.execute(
            "UPDATE local_avatar_selection SET generation=randomblob(16) WHERE singleton=1",
            [],
        )
        .map_err(database_error)?;
        tx.commit().map_err(database_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{dashboard::LocalIdentityProjection, open_store};

    #[test]
    fn avatar_review_rejects_stale_images_identities_and_withdrawn_previews() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("avatar.sqlite3");
        let mut store = open_store(&path).unwrap();
        let owner = AgentId([7; 32]);
        store
            .set_local_identity_projection(&LocalIdentityProjection {
                agent_id: bs58::encode(owner.0).into_string(),
                peer_id: String::new(),
                network_state: "pending_anchor".into(),
                binding_code: String::new(),
            })
            .unwrap();
        store.replace_sanitized_avatar(Some(b"one")).unwrap();
        let review = store.avatar_review().unwrap().unwrap();
        assert!(!review.approved);
        let token = review.token.unwrap();
        assert!(
            store
                .approve_avatar_reference(AgentId([8; 32]), &token)
                .is_err()
        );
        store.approve_avatar_reference(owner, &token).unwrap();
        let original = current_grant(&store.connection, owner).unwrap().unwrap();
        let file_hash = *blake3::hash(b"one").as_bytes();
        let independent = Manifest {
            file_size: 3,
            file_hash,
            chunk_hashes: vec![file_hash],
        };
        assert_eq!(
            original.content_id,
            Hash32(content_id(&encode_manifest(&independent).unwrap()))
        );
        assert_ne!(original.content_id.0, file_hash);
        assert!(store.current_public_profile(owner).unwrap().is_none());
        let mut second = open_store(&path).unwrap();
        second.withdraw_avatar_reference().unwrap();
        assert!(store.approve_avatar_reference(owner, &token).is_err());
        let fresh = store.avatar_review().unwrap().unwrap().token.unwrap();
        second.approve_avatar_reference(owner, &fresh).unwrap();
        assert_ne!(
            original.grant_id,
            current_grant(&store.connection, owner)
                .unwrap()
                .unwrap()
                .grant_id
        );
        for bytes in [b"two", b"one"] {
            second.replace_sanitized_avatar(Some(bytes)).unwrap();
        }
        assert!(current_grant(&store.connection, owner).unwrap().is_none());
        assert!(store.approve_avatar_reference(owner, &fresh).is_err());
        let count: i64 = store.connection.query_row(
            "SELECT (SELECT count(*) FROM resources)+(SELECT count(*) FROM grants)+(SELECT count(*) FROM snapshots)",
            [], |r| r.get(0),
        ).unwrap();
        assert_eq!(count, 0);
        second.replace_sanitized_avatar(None).unwrap();
        assert!(store.avatar_review().unwrap().is_none());
    }

    #[test]
    fn upgrading_v24_preserves_only_a_private_avatar_preview() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.sqlite3");
        let store = open_store(&path).unwrap();
        crate::avatar_receipts::remove_schema_for_legacy_fixture(&store);
        store
            .connection
            .execute_batch(
                "DROP TABLE avatar_reference_grant; DROP TABLE local_avatar_selection;
             DELETE FROM schema_migrations WHERE version>=25;",
            )
            .unwrap();
        store.set_setting(LEGACY_SETTING, "\"706e67\"", 1).unwrap();
        drop(store);
        let mut migrated = open_store(&path).unwrap();
        let preview = migrated.avatar_review().unwrap().unwrap();
        assert_eq!(preview.bytes, b"png");
        assert!(preview.token.is_none() && !preview.approved);
        assert!(
            migrated
                .approve_avatar_reference(AgentId([7; 32]), "")
                .is_err()
        );
    }
}
