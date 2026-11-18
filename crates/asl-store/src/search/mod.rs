//! Local index and scoped queries. A candidate key is never a read capability.
mod index;
mod page;
mod scope;
mod terms;

pub use index::LocalIndexText;
pub(crate) use index::PreparedIndex;
pub use page::{SearchCursor, VisiblePage};

use std::collections::BTreeMap;

use asl_policy::{Permit, PolicyService, Principal, ScopedPolicy};
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32},
    protocol::ConceptRef,
    task::ResourceKey,
};
use rusqlite::{OptionalExtension, params};

use crate::{Store, current_time_ms, database_error};
use scope::Selection;

const MAX_KEYS: usize = 4096;
const MAX_HITS: u32 = 64;

/// Local metadata only. No path, wire serialization, body snippet or model permit.
#[derive(Debug, Clone, PartialEq)]
pub struct SearchHit {
    pub resource_key: ResourceKey,
    pub content_id: Hash32,
    pub local_title: String,
    pub local_summary: String,
    pub local_concept_ids: Vec<ConceptRef>,
    pub score: u32,
}

pub trait ResourceRepository {
    fn visible_keys(&self, principal: &Principal) -> Result<Vec<ResourceKey>, AslError>;
    fn search_visible(
        &self,
        keys: &[ResourceKey],
        concepts: &[ConceptRef],
        limit: u32,
    ) -> Result<Vec<SearchHit>, AslError>;
}

pub struct ResourceSearch<'a> {
    store: &'a Store,
    policy: &'a ScopedPolicy<'a>,
    agent: AgentId,
}

impl Store {
    pub fn peer_search<'a>(
        &'a self,
        policy: &'a ScopedPolicy<'a>,
        agent: AgentId,
    ) -> ResourceSearch<'a> {
        ResourceSearch {
            store: self,
            policy,
            agent,
        }
    }
}

impl ResourceSearch<'_> {
    pub fn visible_keys(&self) -> Result<Vec<ResourceKey>, AslError> {
        let tx = self
            .store
            .connection
            .unchecked_transaction()
            .map_err(database_error)?;
        let revision = self.identity_revision()?;
        let mut keys = Vec::new();
        self.visit_allowed(&tx, revision, Selection::All, |a| {
            if keys.len() == MAX_KEYS {
                return Err(AslError::QuotaExceeded);
            }
            keys.push((a.key, a.search));
            Ok(())
        })?;
        tx.commit().map_err(database_error)?;
        let now = current_time_ms() as u64;
        let keys = keys
            .into_iter()
            .map(|(key, permit)| {
                self.policy
                    .revalidate(&permit, now)
                    .map_err(|_| AslError::PolicyVersionConflict)?;
                Ok(key)
            })
            .collect::<Result<_, AslError>>()?;
        self.check_revision(revision)?;
        Ok(keys)
    }

    /// Only this structured query form is intended for the future peer handler.
    pub fn search_visible(
        &self,
        keys: &[ResourceKey],
        concepts: &[ConceptRef],
        limit: u32,
    ) -> Result<Vec<SearchHit>, AslError> {
        self.search(keys, terms::concept_query(concepts)?, limit, true)
    }

    /// Local diagnostic/task text; never expose a text query in ASL/1.
    pub fn search_local_text(
        &self,
        keys: &[ResourceKey],
        text: &str,
        limit: u32,
    ) -> Result<Vec<SearchHit>, AslError> {
        self.search(keys, terms::text_query(text)?, limit, false)
    }

    fn identity_revision(&self) -> Result<u64, AslError> {
        // Durable tombstones can veto an old device scope, never create one.
        let agent = crate::chain::agent_text(self.agent);
        let peer = bs58::encode(
            self.policy
                .device_peer_id()
                .ok_or(AslError::NotFound)?
                .as_bytes(),
        )
        .into_string();
        let revision: i64=self.store.connection.query_row("SELECT revision FROM policy_state WHERE singleton=1
            AND NOT EXISTS(SELECT 1 FROM identity_registry_states WHERE agent_id=?1 AND status='revoked')
            AND NOT EXISTS(SELECT 1 FROM device_identities WHERE peer_id=?2 AND
                (agent_id<>?1 OR revoked_at_ms IS NOT NULL OR certificate_expires_ms<=?3))",params![agent,peer,current_time_ms()],|r|r.get(0))
            .optional().map_err(database_error)?.ok_or(AslError::NotFound)?;
        u64::try_from(revision).map_err(|_| AslError::InvalidDatabase)
    }

    fn check_revision(&self, revision: u64) -> Result<(), AslError> {
        if self.identity_revision()? != revision {
            return Err(AslError::PolicyVersionConflict);
        }
        Ok(())
    }

    fn search(
        &self,
        keys: &[ResourceKey],
        expr: Option<String>,
        limit: u32,
        concepts: bool,
    ) -> Result<Vec<SearchHit>, AslError> {
        if limit > MAX_HITS || keys.len() > MAX_KEYS {
            return Err(AslError::QuotaExceeded);
        }
        let Some(expr) = expr else { return Ok(vec![]) };
        if keys.is_empty() || limit == 0 {
            return Ok(vec![]);
        }
        let tx = self
            .store
            .connection
            .unchecked_transaction()
            .map_err(database_error)?;
        let revision = self.identity_revision()?;
        let mut allowed = BTreeMap::new();
        self.visit_allowed(&tx, revision, Selection::Keys(keys), |a| {
            if let Some(metadata) = self.metadata_permit(&a, revision)? {
                allowed.insert(a.row, (a, metadata));
            }
            Ok(())
        })?;
        // MATCH is rowid-constrained. Never rank against the global corpus: even
        // the BM25 of a public document could otherwise reveal a private change.
        let matched = if allowed.is_empty() {
            vec![]
        } else {
            let ids = serde_json::to_string(&allowed.keys().collect::<Vec<_>>())
                .map_err(|_| AslError::InvalidPolicyState)?;
            let (query, boost) = if concepts {
                let tag = format!("tag_tokens : ({expr})");
                (tag.clone(), tag)
            } else {
                (
                    format!("{{title_tokens summary_tokens body_tokens}} : ({expr})"),
                    format!("title_tokens : ({expr})"),
                )
            };
            let mut stmt = tx.prepare_cached("SELECT r.row_id,r.title,r.summary,r.tags_json,
                1+EXISTS(SELECT 1 FROM resource_fts b WHERE b.rowid=r.row_id AND b.resource_fts MATCH ?3) AS score
                FROM json_each(?1) k CROSS JOIN resources r ON r.row_id=k.value
                CROSS JOIN resource_fts f ON f.rowid=r.row_id AND f.resource_key=r.resource_key
                WHERE f.resource_fts MATCH ?2 ORDER BY score DESC,r.resource_key LIMIT ?4").map_err(database_error)?;
            let mut rows = stmt
                .query(params![ids, query, boost, limit])
                .map_err(database_error)?;
            let mut hits = Vec::new();
            while let Some(row) = rows.next().map_err(database_error)? {
                let id: i64 = row.get(0).map_err(database_error)?;
                let (a, metadata) = allowed.remove(&id).ok_or(AslError::InvalidDatabase)?;
                let tags = row
                    .get_ref(3)
                    .map_err(database_error)?
                    .as_str()
                    .map_err(|_| AslError::InvalidDatabase)?;
                if tags.len() > 2048 {
                    return Err(AslError::InvalidDatabase);
                }
                let tags: Vec<(u16, u32)> =
                    serde_json::from_str(tags).map_err(|_| AslError::InvalidDatabase)?;
                let local_concept_ids: Vec<_> = tags
                    .into_iter()
                    .map(|(vocabulary_id, concept_id)| ConceptRef {
                        vocabulary_id,
                        concept_id,
                    })
                    .collect();
                terms::concept_tokens(&local_concept_ids).map_err(|_| AslError::InvalidDatabase)?;
                let hit = SearchHit {
                    resource_key: a.key,
                    content_id: a.search.content_id(),
                    local_title: row.get(1).map_err(database_error)?,
                    local_summary: row.get(2).map_err(database_error)?,
                    local_concept_ids,
                    score: row.get(4).map_err(database_error)?,
                };
                hits.push((hit, a.search, metadata));
            }
            hits
        };
        tx.commit().map_err(database_error)?;
        self.check_revision(revision)?;
        let now = current_time_ms() as u64;
        matched
            .into_iter()
            .map(|(hit, search, metadata): (_, Permit, Permit)| {
                self.policy
                    .revalidate(&search, now)
                    .and_then(|()| self.policy.revalidate(&metadata, now))
                    .map_err(|_| AslError::PolicyVersionConflict)?;
                Ok(hit)
            })
            .collect()
    }
}

impl ResourceRepository for ResourceSearch<'_> {
    fn visible_keys(&self, principal: &Principal) -> Result<Vec<ResourceKey>, AslError> {
        if *principal != Principal::Agent(self.agent) {
            return Err(AslError::NotFound);
        }
        self.visible_keys()
    }
    fn search_visible(
        &self,
        keys: &[ResourceKey],
        concepts: &[ConceptRef],
        limit: u32,
    ) -> Result<Vec<SearchHit>, AslError> {
        self.search_visible(keys, concepts, limit)
    }
}
