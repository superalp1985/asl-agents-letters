//! Per-room OpenMLS storage snapshots. These are local-only and are not part
//! of the identity migration format.

#[cfg(test)]
mod tests;

use std::{
    collections::{HashMap, VecDeque},
    fmt,
};

use asl_policy::{protect_secret, unprotect_secret};
use asl_store::group_state::{MAX_SEALED_ROOM_BYTES, MlsRoomSnapshot};
use asl_types::{
    error::AslError,
    ids::{Hash32, PeerId},
    task::GroupId,
};
use openmls::prelude::{GroupId as MlsGroupId, MlsGroup, OpenMlsProvider};
pub use openmls_rust_crypto::OpenMlsRustCrypto as RoomProvider;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{SeqAccess, Visitor},
};
use serde_bytes::{ByteBuf, Bytes};
use zeroize::Zeroizing;

const FORMAT_V1: &str = "ASL-MLS-ROOM-v1";
const FORMAT_V2: &str = "ASL-MLS-ROOM-v2";
const MAX_SYNC_HISTORY: usize = 256;
// Memory-only guard for the shared provider type, outside OpenMLS's labeled keys.
const HISTORY_REQUIRED_KEY: &[u8] = b"\0ASL-MLS-SYNC-HISTORY";

pub struct RoomBinding<'a> {
    pub local_id: &'a GroupId,
    pub wire_id: Hash32,
    pub device: &'a PeerId,
}

/// A rolling window of authenticated digests indexed by consecutive base epochs.
#[derive(Clone, Default)]
pub struct SyncHistory(HistoryWindow);

impl SyncHistory {
    /// Records the digest at the next base epoch, evicting the oldest at capacity.
    pub fn append(&mut self, base_epoch: u64, digest: Hash32) -> Result<(), AslError> {
        if base_epoch == u64::MAX || (!self.is_empty() && self.head_epoch() != Some(base_epoch)) {
            return Err(AslError::InvalidPolicyState);
        }
        if self.is_empty() {
            self.0.first_base_epoch = base_epoch;
        } else if self.0.digests.len() == MAX_SYNC_HISTORY {
            self.0.digests.pop_front();
            // A full window has a representable head greater than its first epoch.
            self.0.first_base_epoch += 1;
        }
        self.0.digests.push_back(digest);
        Ok(())
    }

    pub fn digest(&self, base_epoch: u64) -> Option<Hash32> {
        let index = base_epoch.checked_sub(self.0.first_base_epoch)?;
        self.0.digests.get(usize::try_from(index).ok()?).copied()
    }

    fn is_empty(&self) -> bool {
        self.0.digests.is_empty()
    }

    fn head_epoch(&self) -> Option<u64> {
        self.0
            .first_base_epoch
            .checked_add(self.0.digests.len() as u64)
    }

    fn matches_epoch(&self, epoch: u64) -> bool {
        if self.is_empty() {
            self.0.first_base_epoch == 0
        } else {
            self.head_epoch() == Some(epoch)
        }
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HistoryWindow {
    first_base_epoch: u64,
    #[serde(deserialize_with = "deserialize_digests")]
    digests: VecDeque<Hash32>,
}

fn deserialize_digests<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<VecDeque<Hash32>, D::Error> {
    struct Digests;

    impl<'de> Visitor<'de> for Digests {
        type Value = VecDeque<Hash32>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX_SYNC_HISTORY} sync digests")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut digests = VecDeque::new();
            while let Some(digest) = seq.next_element()? {
                if digests.len() == MAX_SYNC_HISTORY {
                    return Err(serde::de::Error::invalid_length(
                        MAX_SYNC_HISTORY + 1,
                        &self,
                    ));
                }
                digests.push_back(digest);
            }
            Ok(digests)
        }
    }

    deserializer.deserialize_seq(Digests)
}

#[derive(Deserialize, Serialize)]
struct Snapshot<F, D, B, H> {
    format: F,
    room: GroupId,
    wire: Hash32,
    device: D,
    revision: u64,
    epoch: u64,
    records: Vec<(B, B)>,
    // Absence is permitted only in v1. A present field cannot be null.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_history_field",
        bound(deserialize = "H: Deserialize<'de>")
    )]
    history: Option<H>,
}

fn deserialize_history_field<'de, D, H>(deserializer: D) -> Result<Option<H>, D::Error>
where
    D: Deserializer<'de>,
    H: Deserialize<'de>,
{
    H::deserialize(deserializer).map(Some)
}

/// The provider must be dedicated to this room; no MLS state is made
/// available before its SQL commit. Use `seal_with_history` for rooms with
/// sync history.
pub fn seal(
    binding: &RoomBinding<'_>,
    revision: u64,
    group: &MlsGroup,
    provider: &RoomProvider,
) -> Result<Vec<u8>, AslError> {
    seal_snapshot(binding, revision, group, provider, None)
}

/// Seals the MLS state and sync history in one snapshot for the same SQL commit.
pub fn seal_with_history(
    binding: &RoomBinding<'_>,
    revision: u64,
    group: &MlsGroup,
    provider: &RoomProvider,
    history: &SyncHistory,
) -> Result<Vec<u8>, AslError> {
    seal_snapshot(binding, revision, group, provider, Some(history))
}

fn seal_snapshot(
    binding: &RoomBinding<'_>,
    revision: u64,
    group: &MlsGroup,
    provider: &RoomProvider,
    history: Option<&SyncHistory>,
) -> Result<Vec<u8>, AslError> {
    let epoch = group.epoch().as_u64();
    if revision == 0
        || group.group_id().as_slice() != binding.wire_id.as_bytes()
        || history.is_some_and(|history| !history.matches_epoch(epoch))
    {
        return Err(AslError::InvalidPolicyState);
    }
    let mut records = provider
        .storage()
        .values
        .write()
        .map_err(|_| AslError::InvalidPolicyState)?;
    let requires_history = records.contains_key(HISTORY_REQUIRED_KEY);
    let has_history = history.is_some_and(|history| !history.is_empty());
    if requires_history && !has_history {
        return Err(AslError::InvalidPolicyState);
    }
    let mls_records = records
        .iter()
        .filter(|(key, _)| key.as_slice() != HISTORY_REQUIRED_KEY);
    if mls_records.clone().next().is_none()
        || mls_records
            .clone()
            .try_fold(0_usize, |size, (key, value)| {
                size.checked_add(key.len())?.checked_add(value.len())
            })
            .is_none_or(|size| size > MAX_SEALED_ROOM_BYTES)
    {
        return Err(AslError::QuotaExceeded);
    }
    let mut entries = mls_records
        .map(|(key, value)| (Bytes::new(key), Bytes::new(value)))
        .collect::<Vec<_>>();
    entries.sort_unstable_by(|left, right| left.0.cmp(right.0));
    let snapshot = Snapshot {
        format: if history.is_some() {
            FORMAT_V2
        } else {
            FORMAT_V1
        },
        room: binding.local_id.clone(),
        wire: binding.wire_id,
        device: Bytes::new(binding.device.as_bytes()),
        revision,
        epoch,
        records: entries,
        history: history.map(|history| &history.0),
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
    if has_history && !requires_history {
        records.insert(HISTORY_REQUIRED_KEY.to_vec(), Vec::new());
    }
    Ok(sealed)
}

/// Restores a room without history. Refuses history-bearing snapshots so a
/// legacy restore followed by `seal` cannot silently erase the window.
pub fn restore(
    binding: &RoomBinding<'_>,
    row: &MlsRoomSnapshot,
) -> Result<(RoomProvider, MlsGroup), AslError> {
    let (provider, group, history) = restore_with_history(binding, row)?;
    if !history.is_empty() {
        return Err(AslError::IncompatibleVersion);
    }
    Ok((provider, group))
}

/// Restores the MLS state and its sync history. A v1 snapshot has no history.
pub fn restore_with_history(
    binding: &RoomBinding<'_>,
    row: &MlsRoomSnapshot,
) -> Result<(RoomProvider, MlsGroup, SyncHistory), AslError> {
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
    let (snapshot, history) = decode_snapshot(&plaintext)?;
    if snapshot.room != row.local_id
        || snapshot.wire != binding.wire_id
        || snapshot.device.as_ref() != binding.device.as_bytes()
        || snapshot.revision != row.version.revision
        || snapshot.epoch != row.version.mls_epoch
    {
        return Err(AslError::InvalidDatabase);
    }
    let count = snapshot.records.len();
    let mut records: HashMap<_, _> = snapshot
        .records
        .into_iter()
        .map(|(key, value)| (key.into_vec(), value.into_vec()))
        .collect();
    if records.len() != count || records.contains_key(HISTORY_REQUIRED_KEY) {
        return Err(AslError::InvalidDatabase);
    }
    if !history.is_empty() {
        records.insert(HISTORY_REQUIRED_KEY.to_vec(), Vec::new());
    }
    let provider = RoomProvider::default();
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
    Ok((provider, group, history))
}

type StoredSnapshot = Snapshot<String, ByteBuf, ByteBuf, HistoryWindow>;

fn decode_snapshot(plaintext: &[u8]) -> Result<(StoredSnapshot, SyncHistory), AslError> {
    cbor2::validate_slice(plaintext).map_err(|_| AslError::InvalidDatabase)?;
    let mut snapshot: StoredSnapshot =
        cbor2::from_slice(plaintext).map_err(|_| AslError::InvalidDatabase)?;
    let history = match (snapshot.format.as_str(), snapshot.history.take()) {
        (FORMAT_V1, None) => SyncHistory::default(),
        (FORMAT_V2, Some(history)) => SyncHistory(history),
        _ => return Err(AslError::InvalidDatabase),
    };
    if !history.matches_epoch(snapshot.epoch) {
        return Err(AslError::InvalidDatabase);
    }
    Ok((snapshot, history))
}
