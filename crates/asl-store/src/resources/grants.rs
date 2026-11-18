use std::path::{Path, PathBuf};

use asl_policy::reconcile::{MAX_WATCHED_ROOTS, ReconcileDriver};
use asl_policy::{Audience, FileIdentity, SourceGrant, SourceRules};
use asl_types::{error::AslError, task::GrantId};
use rusqlite::{OptionalExtension, params};

use super::{SnapshotBroker, bump_revision, current_time_ms, database_error, immediate, random_id};

const MAX_FILE_BYTES: u64 = 64 << 30;

pub(super) struct ImportAuthority {
    pub(super) id: String,
    pub(super) epoch: i64,
    root: PathBuf,
    identity: FileIdentity,
    extensions: Vec<String>,
    max_bytes: u64,
}

impl ImportAuthority {
    pub(super) fn restore(&self, home: &Path) -> Result<SourceGrant, AslError> {
        let rules = SourceRules::new(
            self.extensions.iter().cloned(),
            self.max_bytes.min(MAX_FILE_BYTES),
        )?;
        SourceGrant::restore(&self.root, home, rules, &self.identity)
    }
}

pub(super) fn file_id(identity: &FileIdentity) -> String {
    format!(
        "{:016x}:{}",
        identity.volume_serial,
        hex::encode(identity.file_id)
    )
}

impl SnapshotBroker {
    /// Watches are hints for existing imports. Excess or unavailable roots still
    /// participate in the periodic sweep and never gain authority from watching.
    pub fn sync_watches(&mut self, driver: &mut ReconcileDriver) -> Result<(), AslError> {
        self.recover_expired_imports()?;
        let mut stmt = self.store.connection.prepare(
            "SELECT min(g.grant_id) FROM grants g WHERE g.status='active' AND EXISTS(
                SELECT 1 FROM resources r WHERE r.grant_id=g.grant_id AND r.active=1 AND r.origin='local')
             GROUP BY g.volume_id,g.root_file_id ORDER BY g.volume_id,g.root_file_id LIMIT ?1"
        ).map_err(database_error)?;
        let ids = stmt
            .query_map([MAX_WATCHED_ROOTS as i64], |r| r.get::<_, String>(0))
            .map_err(database_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(database_error)?;
        let mut roots = Vec::with_capacity(ids.len());
        for id in ids {
            match self.import_authority(&GrantId(super::parse_id(&id)?)) {
                Ok(auth) => roots.push(auth),
                Err(AslError::GrantRevoked) => continue,
                Err(e) => return Err(e),
            }
        }
        driver.retain_watches(&roots.iter().map(|r| r.identity.clone()).collect::<Vec<_>>());
        for auth in roots {
            if let Ok(root) = auth.restore(&self.home) {
                let _ = driver.watch_grant(&root);
            } else {
                driver.unwatch_grant(&auth.identity);
            }
        }
        Ok(())
    }

    /// From an explicit local user authorization only. Does not authorize model input.
    pub fn authorize_directory(
        &mut self,
        root: &Path,
        extensions: &[String],
        audience: &Audience,
        max_snapshot_bytes: u64,
    ) -> Result<GrantId, AslError> {
        let rules = SourceRules::new(
            extensions.iter().cloned(),
            max_snapshot_bytes.min(MAX_FILE_BYTES),
        )?;
        let cap = SourceGrant::open(root, &self.home, rules)?;
        let cap_bytes =
            i64::try_from(max_snapshot_bytes).map_err(|_| AslError::InvalidPolicyState)?;
        let (kind, group) = match audience {
            Audience::Public => ("public", None),
            Audience::Contacts => ("contacts", None),
            Audience::Peers(_) => ("peers", None),
            Audience::Group(g) => ("group", Some(hex::encode(g.0.0))),
        };
        let id = GrantId(random_id());
        let key = hex::encode(id.0.0);
        let extensions =
            serde_json::to_string(extensions).map_err(|_| AslError::InvalidPolicyState)?;
        let tx = immediate(&mut self.store.connection)?;
        tx.execute("INSERT INTO grants(grant_id,root_path,volume_id,root_file_id,extensions_json,audience,group_id,model_policy,max_snapshot_bytes,status,created_at_ms)
            VALUES (?1,?2,?3,?4,?5,?6,?7,'never',?8,'active',?9)",
            params![key,root.to_str().ok_or(AslError::InvalidStorageRoot)?,format!("{:016x}",cap.identity().volume_serial),
                hex::encode(cap.identity().file_id),extensions,kind,group,cap_bytes,current_time_ms()]).map_err(database_error)?;
        if let Audience::Peers(agents) = audience {
            for agent in agents {
                tx.execute(
                    "INSERT INTO grant_agents(grant_id,agent_id) VALUES (?1,?2)",
                    params![key, crate::chain::agent_text(*agent)],
                )
                .map_err(database_error)?;
            }
        }
        bump_revision(&tx)?;
        tx.commit().map_err(database_error)?;
        Ok(id)
    }

    pub fn revoke_directory(&mut self, id: &GrantId) -> Result<(), AslError> {
        let key = hex::encode(id.0.0);
        let tx = immediate(&mut self.store.connection)?;
        if tx.execute("UPDATE grants SET status='revoked',epoch=epoch+1 WHERE grant_id=?1 AND status='active'",[&key]).map_err(database_error)? != 0 {
            tx.execute("UPDATE resources SET active=0,updated_at_ms=?2 WHERE grant_id=?1 AND active=1",
                       params![key,current_time_ms()]).map_err(database_error)?;
            bump_revision(&tx)?;
        }
        tx.commit().map_err(database_error)
    }

    pub(super) fn import_authority(&self, id: &GrantId) -> Result<ImportAuthority, AslError> {
        let id = hex::encode(id.0.0);
        let (root,volume,file,ext,max_bytes,epoch): (String,String,String,String,i64,i64) = self.store.connection.query_row(
            "SELECT root_path,volume_id,root_file_id,extensions_json,max_snapshot_bytes,epoch FROM grants WHERE grant_id=?1 AND status='active'",
            [&id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional().map_err(database_error)?
            .ok_or(AslError::GrantRevoked)?;
        let mut file_id = [0; 16];
        hex::decode_to_slice(file, &mut file_id).map_err(|_| AslError::InvalidDatabase)?;
        Ok(ImportAuthority {
            id,
            epoch,
            root: root.into(),
            extensions: serde_json::from_str(&ext).map_err(|_| AslError::InvalidDatabase)?,
            identity: FileIdentity {
                volume_serial: u64::from_str_radix(&volume, 16)
                    .map_err(|_| AslError::InvalidDatabase)?,
                file_id,
            },
            max_bytes: u64::try_from(max_bytes).map_err(|_| AslError::InvalidDatabase)?,
        })
    }
}
