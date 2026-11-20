//! Per-room OpenMLS storage snapshots. These are local-only and are not part
//! of the identity migration format.

use std::collections::HashMap;

use asl_policy::{protect_secret, unprotect_secret};
use asl_store::group_state::{MAX_SEALED_ROOM_BYTES, MlsRoomSnapshot};
use asl_types::{
    error::AslError,
    ids::{Hash32, PeerId},
    task::GroupId,
};
use openmls::prelude::{GroupId as MlsGroupId, MlsGroup, OpenMlsProvider};
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde::{Deserialize, Serialize};
use serde_bytes::{ByteBuf, Bytes};
use zeroize::Zeroizing;

const FORMAT: &str = "ASL-MLS-ROOM-v1";

pub struct RoomBinding<'a> {
    pub local_id: &'a GroupId,
    pub wire_id: Hash32,
    pub device: &'a PeerId,
}

#[derive(Deserialize, Serialize)]
struct Snapshot<F, D, B> {
    format: F,
    room: GroupId,
    wire: Hash32,
    device: D,
    revision: u64,
    epoch: u64,
    records: Vec<(B, B)>,
}

/// The provider must be dedicated to this room; no MLS state is made
/// available before its SQL commit.
pub fn seal(
    binding: &RoomBinding<'_>,
    revision: u64,
    group: &MlsGroup,
    provider: &OpenMlsRustCrypto,
) -> Result<Vec<u8>, AslError> {
    if revision == 0 || group.group_id().as_slice() != binding.wire_id.as_bytes() {
        return Err(AslError::InvalidPolicyState);
    }
    let records = provider
        .storage()
        .values
        .read()
        .map_err(|_| AslError::InvalidPolicyState)?;
    if records.is_empty()
        || records
            .iter()
            .try_fold(0_usize, |size, (key, value)| {
                size.checked_add(key.len())?.checked_add(value.len())
            })
            .is_none_or(|size| size > MAX_SEALED_ROOM_BYTES)
    {
        return Err(AslError::QuotaExceeded);
    }
    let mut entries = records
        .iter()
        .map(|(key, value)| (Bytes::new(key), Bytes::new(value)))
        .collect::<Vec<_>>();
    entries.sort_unstable_by(|left, right| left.0.cmp(right.0));
    let snapshot = Snapshot {
        format: FORMAT,
        room: binding.local_id.clone(),
        wire: binding.wire_id,
        device: Bytes::new(binding.device.as_bytes()),
        revision,
        epoch: group.epoch().as_u64(),
        records: entries,
    };
    let plaintext =
        Zeroizing::new(cbor2::to_vec(&snapshot).map_err(|_| AslError::InvalidPolicyState)?);
    if plaintext.len() > MAX_SEALED_ROOM_BYTES {
        return Err(AslError::QuotaExceeded);
    }
    let sealed = protect_secret(&plaintext)?;
    if sealed.len() > MAX_SEALED_ROOM_BYTES {
        return Err(AslError::QuotaExceeded);
    }
    Ok(sealed)
}

pub fn restore(
    binding: &RoomBinding<'_>,
    row: &MlsRoomSnapshot,
) -> Result<(OpenMlsRustCrypto, MlsGroup), AslError> {
    if binding.local_id != &row.local_id
        || row.version.revision == 0
        || row.sealed_snapshot.len() > MAX_SEALED_ROOM_BYTES
    {
        return Err(AslError::InvalidDatabase);
    }
    let plaintext = unprotect_secret(&row.sealed_snapshot)?;
    if plaintext.len() > MAX_SEALED_ROOM_BYTES {
        return Err(AslError::InvalidDatabase);
    }
    cbor2::validate_slice(&plaintext).map_err(|_| AslError::InvalidDatabase)?;
    let snapshot: Snapshot<String, ByteBuf, ByteBuf> =
        cbor2::from_slice(&plaintext).map_err(|_| AslError::InvalidDatabase)?;
    if snapshot.format != FORMAT
        || snapshot.room != row.local_id
        || snapshot.wire != binding.wire_id
        || snapshot.device.as_ref() != binding.device.as_bytes()
        || snapshot.revision != row.version.revision
        || snapshot.epoch != row.version.mls_epoch
    {
        return Err(AslError::InvalidDatabase);
    }
    let count = snapshot.records.len();
    let records: HashMap<_, _> = snapshot
        .records
        .into_iter()
        .map(|(key, value)| (key.into_vec(), value.into_vec()))
        .collect();
    if records.len() != count {
        return Err(AslError::InvalidDatabase);
    }
    let provider = OpenMlsRustCrypto::default();
    *provider
        .storage()
        .values
        .write()
        .map_err(|_| AslError::InvalidDatabase)? = records;
    let id = MlsGroupId::from_slice(binding.wire_id.as_bytes());
    let group = MlsGroup::load(provider.storage(), &id)
        .map_err(|_| AslError::InvalidDatabase)?
        .filter(|group| group.group_id() == &id && group.epoch().as_u64() == snapshot.epoch)
        .ok_or(AslError::InvalidDatabase)?;
    Ok((provider, group))
}
