use asl_types::{
    error::AslError,
    ids::Hash32,
    protocol::{
        MAX_SEMANTIC_CONTEXT_BUNDLE_BYTES, SemanticContextRef, SignedSemanticContextBundle,
    },
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::{Store, database_error};

const MAX_CONTEXT_CANDIDATES: i64 = 256;
const MAX_CONTEXT_CACHE_BYTES: i64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticContextCandidateInsert {
    Inserted,
    AlreadyPresent,
}

impl Store {
    /// Stores a structurally valid, content-addressed package candidate.
    ///
    /// This does not authenticate its signature or make its definitions
    /// available to an evaluator. Callers must re-authenticate after reading.
    pub fn put_semantic_context_candidate(
        &mut self,
        bytes: &[u8],
        stored_at_ms: i64,
    ) -> Result<(SemanticContextRef, SemanticContextCandidateInsert), AslError> {
        if stored_at_ms < 0 || bytes.len() > MAX_SEMANTIC_CONTEXT_BUNDLE_BYTES {
            return Err(AslError::InvalidMessage);
        }
        let signed = SignedSemanticContextBundle::decode(bytes)?;
        let canonical = signed.encode()?;
        if canonical != bytes {
            return Err(AslError::InvalidMessage);
        }
        let reference = signed.bundle.context_ref()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;

        let existing = tx
            .query_row(
                "SELECT digest,signed_bundle FROM semantic_context_candidates
                 WHERE authority=?1 AND namespace=?2 AND revision=?3",
                params![
                    reference.authority.as_bytes(),
                    i64::from(reference.namespace),
                    i64::from(reference.revision)
                ],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(database_error)?;
        if let Some((digest, existing_bytes)) = existing {
            let existing_digest: [u8; 32] =
                digest.try_into().map_err(|_| AslError::InvalidDatabase)?;
            if Hash32(existing_digest) != reference.digest || existing_bytes != canonical {
                return Err(AslError::InvalidIdentity);
            }
            tx.commit().map_err(database_error)?;
            return Ok((reference, SemanticContextCandidateInsert::AlreadyPresent));
        }

        let (count, size): (i64, i64) = tx
            .query_row(
                "SELECT COUNT(*),COALESCE(SUM(length(signed_bundle)),0)
                 FROM semantic_context_candidates",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(database_error)?;
        let new_size = i64::try_from(canonical.len()).map_err(|_| AslError::QuotaExceeded)?;
        if count >= MAX_CONTEXT_CANDIDATES
            || size
                .checked_add(new_size)
                .is_none_or(|total| total > MAX_CONTEXT_CACHE_BYTES)
        {
            return Err(AslError::QuotaExceeded);
        }

        tx.execute(
            "INSERT INTO semantic_context_candidates(
                authority,namespace,revision,digest,signed_bundle,stored_at_ms
             ) VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                reference.authority.as_bytes(),
                i64::from(reference.namespace),
                i64::from(reference.revision),
                reference.digest.as_bytes(),
                canonical,
                stored_at_ms
            ],
        )
        .map_err(database_error)?;
        tx.commit().map_err(database_error)?;
        Ok((reference, SemanticContextCandidateInsert::Inserted))
    }

    /// Reads untrusted candidate bytes. Signature and dependency verification
    /// is deliberately performed by `asl-app` on every use.
    pub fn semantic_context_candidate(
        &self,
        reference: SemanticContextRef,
    ) -> Result<Option<Vec<u8>>, AslError> {
        let bytes = self
            .connection
            .query_row(
                "SELECT signed_bundle FROM semantic_context_candidates
                 WHERE authority=?1 AND namespace=?2 AND revision=?3 AND digest=?4",
                params![
                    reference.authority.as_bytes(),
                    i64::from(reference.namespace),
                    i64::from(reference.revision),
                    reference.digest.as_bytes()
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(database_error)?;
        let Some(bytes) = bytes else {
            return Ok(None);
        };
        let signed = SignedSemanticContextBundle::decode(&bytes)?;
        if signed.bundle.context_ref()? != reference {
            return Err(AslError::InvalidDatabase);
        }
        Ok(Some(bytes))
    }

    pub fn remove_semantic_context_candidate(
        &mut self,
        reference: SemanticContextRef,
    ) -> Result<bool, AslError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let removed = tx
            .execute(
                "DELETE FROM semantic_context_candidates
                 WHERE authority=?1 AND namespace=?2 AND revision=?3 AND digest=?4",
                params![
                    reference.authority.as_bytes(),
                    i64::from(reference.namespace),
                    i64::from(reference.revision),
                    reference.digest.as_bytes()
                ],
            )
            .map_err(database_error)?;
        tx.commit().map_err(database_error)?;
        Ok(removed == 1)
    }
}
