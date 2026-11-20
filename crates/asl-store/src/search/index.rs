use asl_types::{error::AslError, ids::Hash32, protocol::ConceptRef, task::ResourceKey};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use super::terms;
use crate::{Store, database_error};

/// Core-local source or extractor output, never peer-supplied search metadata.
pub struct LocalIndexText<'a> {
    pub title: &'a str,
    pub summary: &'a str,
    pub body: &'a str,
    pub concepts: &'a [ConceptRef],
}

pub(crate) struct PreparedIndex {
    local_title: String,
    local_summary: String,
    title: String,
    summary: String,
    body: String,
    tags: String,
    concepts_json: String,
}

impl PreparedIndex {
    pub(crate) fn new(text: LocalIndexText<'_>) -> Result<Self, AslError> {
        if text.title.len() > 640
            || text.title.chars().count() > 160
            || text.summary.len() > 4800
            || text.summary.chars().count() > 1200
            || text.body.len() > 32 * 1024
            || [text.title, text.summary, text.body]
                .iter()
                .any(|v| v.contains('\0'))
        {
            return Err(AslError::InvalidMessage);
        }
        let tags = terms::concept_tokens(text.concepts)?;
        let pairs: Vec<_> = text
            .concepts
            .iter()
            .map(|c| (c.vocabulary_id, c.concept_id))
            .collect();
        Ok(Self {
            title: terms::tokens(text.title),
            summary: terms::tokens(text.summary),
            body: terms::tokens(text.body),
            tags,
            concepts_json: serde_json::to_string(&pairs).map_err(|_| AslError::InvalidMessage)?,
            local_title: text.title.to_owned(),
            local_summary: text.summary.to_owned(),
        })
    }

    /// Caller owns the write transaction, including any new resource reference.
    pub(crate) fn write(
        &self,
        db: &Connection,
        key: &ResourceKey,
        expected: Hash32,
    ) -> Result<(), AslError> {
        let key = hex::encode(key.0.0);
        let row: i64 = db.query_row("UPDATE resources SET title=?3,summary=?4,tags_json=?5
            WHERE resource_key=?1 AND content_id=?2 AND origin IN ('local','derived') AND active=1
            AND EXISTS(SELECT 1 FROM grants g WHERE g.grant_id=resources.grant_id
                AND g.status='active' AND g.epoch=resources.source_grant_epoch)
            AND EXISTS(SELECT 1 FROM snapshots s WHERE s.content_id=resources.content_id AND s.state='ready')
            RETURNING row_id", params![key,hex::encode(expected.0),self.local_title,self.local_summary,self.concepts_json],
            |r|r.get(0)).optional().map_err(database_error)?.ok_or(AslError::NotFound)?;
        db.execute("INSERT OR REPLACE INTO resource_fts(rowid,resource_key,title_tokens,summary_tokens,body_tokens,tag_tokens)
            VALUES(?1,?2,?3,?4,?5,?6)", params![row,key,self.title,self.summary,self.body,self.tags]).map_err(database_error)?;
        Ok(())
    }
}

impl Store {
    /// Enrich only an already imported, active reference to these exact bytes.
    pub fn index_local_text(
        &mut self,
        key: &ResourceKey,
        content: Hash32,
        text: LocalIndexText<'_>,
    ) -> Result<(), AslError> {
        let prepared = PreparedIndex::new(text)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        prepared.write(&tx, key, content)?;
        tx.commit().map_err(database_error)
    }
}
