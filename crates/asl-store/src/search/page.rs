use asl_policy::PolicyService;
use asl_types::{error::AslError, task::ResourceKey};
use rusqlite::Connection;

use super::{
    ResourceSearch,
    scope::{Selection, physical_page},
};
use crate::{current_time_ms, database_error};

/// An in-process continuation tied to the issuing search handle. Never send to a peer.
pub struct SearchCursor<'a> {
    search: &'a ResourceSearch<'a>,
    first: i64,
    revision: u64,
    stamp: DbStamp,
}

/// Local only: even the presence of a continuation can reveal private rows.
pub struct VisiblePage<'a> {
    pub keys: Vec<ResourceKey>,
    pub next: Option<SearchCursor<'a>>,
}

#[derive(Clone, Copy, PartialEq)]
struct DbStamp {
    external: i64,
    local: u64,
}

impl DbStamp {
    fn read(db: &Connection) -> Result<Self, AslError> {
        // data_version tracks commits on other connections; total_changes covers ours.
        Ok(Self {
            external: db
                .pragma_query_value(Some("main"), "data_version", |r| r.get(0))
                .map_err(database_error)?,
            local: db.total_changes(),
        })
    }
}

impl ResourceSearch<'_> {
    /// Scan 1..=4096 physical candidates in rowid order (plus one ID of lookahead).
    /// A filtered page can be empty. Follow `next` until `None`, restarting on
    /// conflict. Any intervening database write may invalidate the traversal.
    /// Neither this page nor its continuation belongs in a peer response.
    pub fn visible_keys_page<'a>(
        &'a self,
        cursor: Option<&SearchCursor<'a>>,
        budget: u32,
    ) -> Result<VisiblePage<'a>, AslError> {
        let db = &self.store.connection;
        let tx = db.unchecked_transaction().map_err(database_error)?;
        let revision = self.identity_revision()?;
        let stamp = DbStamp::read(&tx)?;
        let first = match cursor {
            None => i64::MIN,
            Some(c)
                if std::ptr::eq(self, c.search) && c.revision == revision && c.stamp == stamp =>
            {
                c.first
            }
            Some(_) => return Err(AslError::PolicyVersionConflict),
        };
        let (rows, next) = physical_page(&tx, first, budget)?;
        let mut pending = Vec::new();
        self.visit_allowed(&tx, revision, Selection::Page(&rows), |a| {
            pending.push((a.key, a.search));
            Ok(())
        })?;
        tx.commit().map_err(database_error)?;
        let now = current_time_ms() as u64;
        let mut keys = Vec::with_capacity(pending.len());
        for (key, permit) in pending {
            self.policy
                .revalidate(&permit, now)
                .map_err(|_| AslError::PolicyVersionConflict)?;
            keys.push(key);
        }
        self.check_revision(revision)?;
        if DbStamp::read(db)? != stamp {
            return Err(AslError::PolicyVersionConflict);
        }
        Ok(VisiblePage {
            keys,
            next: next.map(|first| SearchCursor {
                search: self,
                first,
                revision,
                stamp,
            }),
        })
    }
}
