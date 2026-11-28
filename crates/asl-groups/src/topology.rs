use asl_types::{
    error::AslError,
    ids::{Hash32, PeerId},
};

pub const MAX_DIRECT_SHARD_MEMBERS: usize = 512;
pub const MAX_LAYERED_MEMBERS: usize = 10_000;
pub const MAX_SHARD_RELAY_HOPS: u8 = 4;
pub const MAX_SHARD_ENVELOPE_BYTES: usize = 64 * 1024 - 52;

const SHARD_TOPIC_DOMAIN: &[u8] = b"ASL-GROUP-SHARD-TOPIC-v1\0";
const BACKBONE_TOPIC_DOMAIN: &[u8] = b"ASL-GROUP-BACKBONE-TOPIC-v1\0";
const ROUTE_MAGIC: &[u8; 4] = b"ASLG";
const ROUTE_VERSION: u8 = 1;
const ROUTE_HEADER_BYTES: usize = 52;

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupShardRoute {
    pub local_shard: u16,
    pub bridge: PeerId,
    pub is_bridge: bool,
    pub shard_topic: [u8; 32],
    pub backbone_topic: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupGossipRoute {
    pub room: Hash32,
    pub origin_shard: u16,
    pub hop: u8,
    pub envelope: Vec<u8>,
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

pub fn route_for_room(
    room: Hash32,
    plan: &GroupShardPlan,
    local: &PeerId,
) -> Option<GroupShardRoute> {
    let shard = plan
        .shards
        .iter()
        .find(|shard| shard.members.iter().any(|member| member == local))?;
    Some(GroupShardRoute {
        local_shard: shard.index,
        bridge: shard.bridge.clone(),
        is_bridge: &shard.bridge == local,
        shard_topic: shard_topic(room, shard.index),
        backbone_topic: backbone_topic(room),
    })
}

pub fn shard_topic(room: Hash32, shard_index: u16) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SHARD_TOPIC_DOMAIN);
    hasher.update(room.as_bytes());
    hasher.update(&shard_index.to_be_bytes());
    *hasher.finalize().as_bytes()
}

pub fn backbone_topic(room: Hash32) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(BACKBONE_TOPIC_DOMAIN);
    hasher.update(room.as_bytes());
    *hasher.finalize().as_bytes()
}

impl GroupGossipRoute {
    pub fn encode(&self) -> Result<Vec<u8>, AslError> {
        if self.room.0 == [0; 32]
            || self.hop > MAX_SHARD_RELAY_HOPS
            || self.envelope.is_empty()
            || self.envelope.len() > MAX_SHARD_ENVELOPE_BYTES
        {
            return Err(AslError::InvalidMessage);
        }
        let length = u32::try_from(self.envelope.len()).map_err(|_| AslError::QuotaExceeded)?;
        let mut bytes = Vec::with_capacity(ROUTE_HEADER_BYTES + self.envelope.len());
        bytes.extend_from_slice(ROUTE_MAGIC);
        bytes.push(ROUTE_VERSION);
        bytes.push(self.hop);
        bytes.extend_from_slice(&self.origin_shard.to_be_bytes());
        bytes.extend_from_slice(&[0; 8]);
        bytes.extend_from_slice(self.room.as_bytes());
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&self.envelope);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AslError> {
        if bytes.len() <= ROUTE_HEADER_BYTES
            || bytes.len() > ROUTE_HEADER_BYTES + MAX_SHARD_ENVELOPE_BYTES
            || &bytes[..4] != ROUTE_MAGIC
            || bytes[4] != ROUTE_VERSION
            || bytes[8..16] != [0; 8]
        {
            return Err(AslError::InvalidMessage);
        }
        let hop = bytes[5];
        if hop > MAX_SHARD_RELAY_HOPS {
            return Err(AslError::InvalidMessage);
        }
        let origin_shard = u16::from_be_bytes([bytes[6], bytes[7]]);
        let room = Hash32(
            bytes[16..48]
                .try_into()
                .map_err(|_| AslError::InvalidMessage)?,
        );
        if room.0 == [0; 32] {
            return Err(AslError::InvalidMessage);
        }
        let length = u32::from_be_bytes(
            bytes[48..52]
                .try_into()
                .map_err(|_| AslError::InvalidMessage)?,
        );
        let length = usize::try_from(length).map_err(|_| AslError::InvalidMessage)?;
        if length == 0
            || length > MAX_SHARD_ENVELOPE_BYTES
            || bytes.len() != ROUTE_HEADER_BYTES + length
        {
            return Err(AslError::InvalidMessage);
        }
        Ok(Self {
            room,
            origin_shard,
            hop,
            envelope: bytes[ROUTE_HEADER_BYTES..].to_vec(),
        })
    }

    pub fn forwarded(&self) -> Result<Self, AslError> {
        if self.hop >= MAX_SHARD_RELAY_HOPS {
            return Err(AslError::QuotaExceeded);
        }
        let mut route = self.clone();
        route.hop += 1;
        Ok(route)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(seed: u8) -> PeerId {
        let key = libp2p_identity::Keypair::ed25519_from_bytes([seed; 32])
            .unwrap()
            .public()
            .to_peer_id();
        PeerId::from_bytes(key.to_bytes()).unwrap()
    }

    #[test]
    fn routing_plan_is_deterministic_and_never_loses_members() {
        let members = (1..=5).map(peer).collect();
        let plan = plan_group_shards(members, 2).unwrap();
        assert_eq!(plan.shards.len(), 3);
        assert_eq!(
            plan.shards
                .iter()
                .flat_map(|shard| shard.members.iter())
                .count(),
            5
        );
        let route = route_for_room(Hash32([7; 32]), &plan, &plan.shards[1].bridge).unwrap();
        assert_eq!(route.local_shard, 1);
        assert!(route.is_bridge);
        assert_eq!(route.shard_topic, shard_topic(Hash32([7; 32]), 1));
    }

    #[test]
    fn gossip_route_is_bounded_and_round_trips() {
        let route = GroupGossipRoute {
            room: Hash32([1; 32]),
            origin_shard: 3,
            hop: 0,
            envelope: vec![1, 2, 3],
        };
        assert_eq!(
            GroupGossipRoute::decode(&route.encode().unwrap()).unwrap(),
            route
        );
        assert!(route.forwarded().unwrap().hop == 1);

        let mut invalid = route;
        invalid.envelope.clear();
        assert!(invalid.encode().is_err());
    }

    #[test]
    fn ten_thousand_member_plan_is_bounded_to_twenty_shards() {
        let members = (0..MAX_LAYERED_MEMBERS)
            .map(|index| {
                let mut bytes = [0; 32];
                bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
                let key = libp2p_identity::Keypair::ed25519_from_bytes(bytes)
                    .unwrap()
                    .public()
                    .to_peer_id();
                PeerId::from_bytes(key.to_bytes()).unwrap()
            })
            .collect();
        let plan = plan_group_shards(members, MAX_DIRECT_SHARD_MEMBERS).unwrap();
        assert_eq!(plan.shards.len(), 20);
        assert!(
            plan.shards
                .iter()
                .all(|shard| shard.members.len() <= MAX_DIRECT_SHARD_MEMBERS)
        );
    }
}
