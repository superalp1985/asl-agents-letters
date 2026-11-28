use asl_types::{
    error::AslError,
    ids::{Hash32, PeerId},
    protocol::{ShardBinding, ShardForward},
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::{sql_number, transition::peer_text};
use crate::{Store, database_error};

impl Store {
    pub fn shard_binding_revision(&self, child: Hash32) -> Result<Option<u64>, AslError> {
        self.connection
            .query_row(
                "SELECT revision FROM mls_shard_bindings WHERE child_wire_id=?1",
                [child.as_bytes()],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(database_error)?
            .map(|revision| u64::try_from(revision).map_err(|_| AslError::InvalidDatabase))
            .transpose()
    }

    pub fn store_shard_binding(
        &mut self,
        binding: &ShardBinding,
        sender: &PeerId,
        now_ms: u64,
    ) -> Result<bool, AslError> {
        binding.validate_at(now_ms)?;
        if sender != &binding.owner_peer
            || self.group_access_owner(binding.child)?.as_ref() != Some(sender)
            || self.mls_peer_agent(sender)? != Some(binding.owner_agent)
            || !self.has_mls_sync_member(binding.child, sender)?
        {
            return Err(AslError::PolicyDenied);
        }
        if let Some((root, index)) = self.mls_shard_parent(binding.child)?
            && (root != binding.logical_root || index != binding.shard_index)
        {
            return Err(AslError::PolicyVersionConflict);
        }
        let encoded = binding.encode()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let previous = tx
            .query_row(
                "SELECT revision,binding_cbor FROM mls_shard_bindings WHERE child_wire_id=?1",
                [binding.child.as_bytes()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(database_error)?;
        if let Some((revision, bytes)) = previous {
            let revision = u64::try_from(revision).map_err(|_| AslError::InvalidDatabase)?;
            if revision > binding.revision || (revision == binding.revision && bytes != encoded) {
                return Err(AslError::PolicyVersionConflict);
            }
            if revision == binding.revision {
                tx.commit().map_err(database_error)?;
                return Ok(false);
            }
        }
        tx.execute(
            "INSERT INTO mls_shard_bindings(
                child_wire_id,root_wire_id,shard_index,owner_agent_id,owner_peer_id,
                revision,issued_at_ms,expires_at_ms,binding_cbor)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
             ON CONFLICT(child_wire_id) DO UPDATE SET
                root_wire_id=excluded.root_wire_id,shard_index=excluded.shard_index,
                owner_agent_id=excluded.owner_agent_id,owner_peer_id=excluded.owner_peer_id,
                revision=excluded.revision,issued_at_ms=excluded.issued_at_ms,
                expires_at_ms=excluded.expires_at_ms,binding_cbor=excluded.binding_cbor",
            params![
                binding.child.as_bytes(),
                binding.logical_root.as_bytes(),
                i64::from(binding.shard_index),
                binding.owner_agent.as_bytes(),
                peer_text(&binding.owner_peer),
                sql_number(binding.revision)?,
                sql_number(binding.issued_at_ms)?,
                sql_number(binding.expires_at_ms)?,
                encoded,
            ],
        )
        .map_err(database_error)?;
        tx.commit().map_err(database_error)?;
        Ok(true)
    }

    pub fn shard_binding(
        &self,
        child: Hash32,
        now_ms: u64,
    ) -> Result<Option<ShardBinding>, AslError> {
        self.connection
            .query_row(
                "SELECT binding_cbor FROM mls_shard_bindings
                 WHERE child_wire_id=?1 AND expires_at_ms>?2",
                params![child.as_bytes(), sql_number(now_ms)?],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(database_error)?
            .map(|bytes| {
                let binding = ShardBinding::decode(&bytes)?;
                binding.validate_at(now_ms)?;
                Ok(binding)
            })
            .transpose()
    }

    pub fn claim_shard_forward(
        &mut self,
        forward: &ShardForward,
        outer_sender: &PeerId,
        now_ms: u64,
    ) -> Result<bool, AslError> {
        forward.validate_at(now_ms)?;
        if outer_sender != &forward.attestor_peer
            || self.group_access_owner(forward.target_child)?.as_ref()
                != Some(&forward.attestor_peer)
        {
            return Err(AslError::PolicyDenied);
        }
        if forward.target_child == forward.logical_root {
            if forward.target_binding.is_some() {
                return Err(AslError::InvalidMessage);
            }
        } else {
            let stored = self
                .shard_binding(forward.target_child, now_ms)?
                .ok_or(AslError::PolicyDenied)?;
            if forward.target_binding.as_ref() != Some(&stored) {
                return Err(AslError::PolicyVersionConflict);
            }
        }
        self.record_shard_forward_receipt(forward, now_ms)
    }

    pub fn shard_forward_recorded(
        &self,
        forward: &ShardForward,
        now_ms: u64,
    ) -> Result<bool, AslError> {
        self.connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM mls_shard_forward_receipts
                 WHERE root_wire_id=?1 AND source_wire_id=?2 AND target_wire_id=?3
                   AND source_peer_id=?4 AND source_message_id=?5 AND expires_at_ms>?6)",
                params![
                    forward.logical_root.as_bytes(),
                    forward.source_child.as_bytes(),
                    forward.target_child.as_bytes(),
                    peer_text(&forward.source_peer),
                    forward.source_message_id.0.as_slice(),
                    sql_number(now_ms)?,
                ],
                |row| row.get(0),
            )
            .map_err(database_error)
    }

    pub fn record_shard_forward_receipt(
        &mut self,
        forward: &ShardForward,
        now_ms: u64,
    ) -> Result<bool, AslError> {
        forward.validate_at(now_ms)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        tx.execute(
            "DELETE FROM mls_shard_forward_receipts WHERE expires_at_ms<=?1",
            [sql_number(now_ms)?],
        )
        .map_err(database_error)?;
        let changed = tx
            .execute(
                "INSERT OR IGNORE INTO mls_shard_forward_receipts(
                    root_wire_id,source_wire_id,target_wire_id,source_agent_id,source_peer_id,
                    source_message_id,observed_at_ms,expires_at_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    forward.logical_root.as_bytes(),
                    forward.source_child.as_bytes(),
                    forward.target_child.as_bytes(),
                    forward.source_agent.as_bytes(),
                    peer_text(&forward.source_peer),
                    forward.source_message_id.0.as_slice(),
                    sql_number(forward.observed_at_ms)?,
                    sql_number(forward.expires_at_ms)?,
                ],
            )
            .map_err(database_error)?
            != 0;
        tx.commit().map_err(database_error)?;
        Ok(changed)
    }
}
