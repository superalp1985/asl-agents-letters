use asl_types::{error::AslError, ids::PeerId};

pub const MAX_DIRECT_SHARD_MEMBERS: usize = 512;
pub const MAX_LAYERED_MEMBERS: usize = 10_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupShardPlan {
    pub shards: Vec<GroupShard>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupShard {
    pub index: u16,
    pub bridge: PeerId,
    pub members: Vec<PeerId>,
}

/// Deterministically partitions an already authenticated member set into
/// direct MLS shards. The bridge is the lowest-sorted member in the shard and
/// is the only member expected to participate in inter-shard relay topics.
pub fn plan_group_shards(
    mut members: Vec<PeerId>,
    max_per_shard: usize,
) -> Result<GroupShardPlan, AslError> {
    let limit = max_per_shard.min(MAX_DIRECT_SHARD_MEMBERS);
    if limit == 0 || members.is_empty() || members.len() > MAX_LAYERED_MEMBERS {
        return Err(AslError::InvalidMessage);
    }
    members.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    members.dedup();
    if members.is_empty() {
        return Err(AslError::InvalidMessage);
    }
    let mut shards = Vec::with_capacity(members.len().div_ceil(limit));
    for (index, chunk) in members.chunks(limit).enumerate() {
        shards.push(GroupShard {
            index: u16::try_from(index).map_err(|_| AslError::QuotaExceeded)?,
            bridge: chunk[0].clone(),
            members: chunk.to_vec(),
        });
    }
    Ok(GroupShardPlan { shards })
}
