use std::path::Path;

use asl_policy::{
    FileIdentity, open_authorized_source,
    reconcile::{ActivePage, PAGE_SIZE, ReconcileBackend, SourceCheck, check_source_with_progress},
};
use asl_types::{
    error::AslError,
    ids::Hash32,
    task::{GrantId, ResourceKey},
};
use rusqlite::{OptionalExtension, params};

use super::{SnapshotBroker, bump_revision, current_time_ms, database_error, immediate, parse_id};

struct LocalSource {
    grant: String,
    relative: String,
    source_id: String,
    content: String,
    hash: String,
    size: i64,
    epoch: i64,
}

impl SnapshotBroker {
    /// Rechecks a reference, never makes it active or gives an agent permission.
    pub fn refresh_source(&mut self, key: &ResourceKey) -> Result<bool, AslError> {
        let key = hex::encode(key.0.0);
        let source = self.store.connection.query_row(
            "SELECT grant_id,source_relative,source_file_id,content_id,file_hash,file_size,epoch FROM resources r
             JOIN snapshots s USING(content_id) JOIN grants g USING(grant_id) WHERE r.resource_key=?1
             AND r.active=1 AND r.origin='local' AND s.state='ready' AND g.status='active' AND r.source_grant_epoch=g.epoch",
            [&key], |r|Ok(LocalSource {grant:r.get(0)?,relative:r.get(1)?,source_id:r.get(2)?,content:r.get(3)?,hash:r.get(4)?,size:r.get(5)?,epoch:r.get(6)?})
        ).optional().map_err(database_error)?;
        let Some(s) = source else { return Ok(false) };
        let (volume, file) = s
            .source_id
            .split_once(':')
            .ok_or(AslError::InvalidDatabase)?;
        let expected_id = FileIdentity {
            volume_serial: u64::from_str_radix(volume, 16)
                .map_err(|_| AslError::InvalidDatabase)?,
            file_id: parse_id(file)?.0,
        };
        let mut hash = [0; 32];
        hex::decode_to_slice(&s.hash, &mut hash).map_err(|_| AslError::InvalidDatabase)?;
        let opened = self
            .import_authority(&GrantId(parse_id(&s.grant)?))
            .and_then(|auth| auth.restore(&self.home))
            .and_then(|grant| open_authorized_source(&grant, Path::new(&s.relative)));
        let checked = check_source_with_progress(
            opened,
            &expected_id,
            u64::try_from(s.size).map_err(|_| AslError::InvalidDatabase)?,
            &Hash32(hash),
            || {
                if self
                    .reconcile_stop
                    .as_ref()
                    .is_some_and(|stop| stop.load(std::sync::atomic::Ordering::Acquire))
                {
                    return Err(std::io::Error::from(std::io::ErrorKind::Interrupted).into());
                }
                Ok(())
            },
        )?;
        // An unchanged source only needs a consistent read. Reserve the
        // writer for an actual invalidation, not every file in a sweep.
        let tx = match checked {
            SourceCheck::Unchanged => self
                .store
                .connection
                .transaction()
                .map_err(database_error)?,
            SourceCheck::Deactivate => immediate(&mut self.store.connection)?,
        };
        let current: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM resources r JOIN grants g USING(grant_id) JOIN snapshots s USING(content_id)
            WHERE r.resource_key=?1 AND r.active=1 AND r.grant_id=?2 AND r.content_id=?3 AND r.source_file_id=?4 AND r.source_relative=?5
            AND r.origin='local' AND g.epoch=?6 AND r.source_grant_epoch=g.epoch AND g.status='active' AND s.state='ready')",
            params![key,s.grant,s.content,s.source_id,s.relative,s.epoch],|r|r.get(0)).map_err(database_error)?;
        if current && checked == SourceCheck::Deactivate {
            tx.execute(
                "UPDATE resources SET active=0,updated_at_ms=?2 WHERE resource_key=?1",
                params![key, current_time_ms()],
            )
            .map_err(database_error)?;
            bump_revision(&tx)?;
        }
        tx.commit().map_err(database_error)?;
        Ok(current && checked == SourceCheck::Unchanged)
    }
}

impl ReconcileBackend for SnapshotBroker {
    fn last_active_row(&mut self) -> Result<Option<i64>, AslError> {
        self.store
            .connection
            .query_row(
                "SELECT max(row_id) FROM resources WHERE active=1 AND origin='local'",
                [],
                |r| r.get(0),
            )
            .map_err(database_error)
    }

    fn active_page(
        &mut self,
        after: Option<i64>,
        through: i64,
        page: &mut ActivePage,
    ) -> Result<(), AslError> {
        let mut stmt = self
            .store
            .connection
            .prepare(
                "SELECT row_id,resource_key FROM resources WHERE active=1 AND origin='local'
            AND row_id>coalesce(?1,0) AND row_id<=?2 ORDER BY row_id LIMIT ?3",
            )
            .map_err(database_error)?;
        let mut rows = stmt
            .query(params![after, through, PAGE_SIZE as i64])
            .map_err(database_error)?;
        while let Some(row) = rows.next().map_err(database_error)? {
            let key: String = row.get(1).map_err(database_error)?;
            page.push(
                row.get(0).map_err(database_error)?,
                ResourceKey(parse_id(&key)?),
            )?;
        }
        Ok(())
    }

    fn reconcile_one(&mut self, key: &ResourceKey) -> Result<(), AslError> {
        self.refresh_source(key).map(|_| ())
    }
}
