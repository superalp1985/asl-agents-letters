use asl_groups::topology::{
    GroupGossipRoute, GroupShardPlan, MAX_DIRECT_SHARD_MEMBERS, plan_group_shards, route_for_room,
};
use asl_store::Store;
use asl_types::{
    error::AslError,
    ids::{Hash32, PeerId},
    protocol::{GroupPacket, WireFrame, encode_frame},
};

use crate::{network::NetworkCommand, profile::fresh_id, supervisor::NetRuntime};

pub(super) struct IncomingGroupPacket {
    pub room: Hash32,
    pub packet: GroupPacket,
    pub forward: Option<([u8; 32], Vec<u8>)>,
}

pub(super) fn plan_for_room(
    store: &Store,
    room: Hash32,
) -> Result<Option<GroupShardPlan>, AslError> {
    let snapshot = store.mls_room_snapshot(room)?.ok_or(AslError::NotFound)?;
    let members = store.group_topology_members(&snapshot.local_id)?;
    if members.len() <= MAX_DIRECT_SHARD_MEMBERS {
        return Ok(None);
    }
    plan_group_shards(members, MAX_DIRECT_SHARD_MEMBERS).map(Some)
}

pub(super) fn topics_for_room(
    store: &Store,
    room: Hash32,
    local: &PeerId,
) -> Result<Vec<Hash32>, AslError> {
    let Some(plan) = plan_for_room(store, room)? else {
        return Ok(vec![room]);
    };
    let route = route_for_room(room, &plan, local).ok_or(AslError::PolicyDenied)?;
    let mut topics = vec![Hash32(route.shard_topic)];
    if route.is_bridge {
        topics.push(Hash32(route.backbone_topic));
    }
    Ok(topics)
}

pub(super) fn publish_packet(
    net: &NetRuntime,
    store: &Store,
    room: Hash32,
    local: &PeerId,
    packet: &GroupPacket,
) -> Result<(), AslError> {
    let payload = encode_frame(&WireFrame::GroupEnvelope(packet.clone().into_envelope()?))?;
    let Some(plan) = plan_for_room(store, room)? else {
        return publish(net, room.0, payload);
    };
    let route = route_for_room(room, &plan, local).ok_or(AslError::PolicyDenied)?;
    let routed = GroupGossipRoute {
        room,
        origin_shard: route.local_shard,
        hop: 0,
        envelope: payload,
    }
    .encode()?;
    publish(net, route.shard_topic, routed.clone())?;
    publish(net, route.backbone_topic, routed)
}

pub(super) fn decode_incoming(
    store: &Store,
    topic: Hash32,
    payload: &[u8],
    local: &PeerId,
) -> Result<IncomingGroupPacket, AslError> {
    let (room, envelope, route) = if let Ok(route) = GroupGossipRoute::decode(payload) {
        let WireFrame::GroupEnvelope(envelope) =
            asl_types::protocol::decode_frame(&route.envelope)?
        else {
            return Err(AslError::InvalidMessage);
        };
        (route.room, envelope, Some(route))
    } else {
        let WireFrame::GroupEnvelope(envelope) = asl_types::protocol::decode_frame(payload)? else {
            return Err(AslError::InvalidMessage);
        };
        (envelope.group_id, envelope, None)
    };
    let packet = GroupPacket::from_envelope(envelope)?;
    if packet.group_id != room {
        return Err(AslError::InvalidMessage);
    }
    let Some(route) = route else {
        return (topic == room)
            .then_some(IncomingGroupPacket {
                room,
                packet,
                forward: None,
            })
            .ok_or(AslError::PolicyDenied);
    };
    let plan = plan_for_room(store, room)?.ok_or(AslError::PolicyDenied)?;
    let local_route = route_for_room(room, &plan, local).ok_or(AslError::PolicyDenied)?;
    if usize::from(route.origin_shard) >= plan.shards.len()
        || (topic.0 != local_route.shard_topic
            && !(local_route.is_bridge && topic.0 == local_route.backbone_topic))
    {
        return Err(AslError::PolicyDenied);
    }
    let forward = if topic.0 == local_route.backbone_topic
        && local_route.is_bridge
        && route.origin_shard != local_route.local_shard
    {
        Some((local_route.shard_topic, route.forwarded()?.encode()?))
    } else {
        None
    };
    Ok(IncomingGroupPacket {
        room,
        packet,
        forward,
    })
}

pub(super) fn forward_packet(
    net: &NetRuntime,
    topic: [u8; 32],
    payload: Vec<u8>,
) -> Result<(), AslError> {
    publish(net, topic, payload)
}

fn publish(net: &NetRuntime, key: [u8; 32], payload: Vec<u8>) -> Result<(), AslError> {
    if net.try_send(
        &NetworkCommand::GossipPublish {
            operation_id: fresh_id()?,
            key,
            payload,
        }
        .into_ipc()?,
    )? {
        Ok(())
    } else {
        Err(AslError::QuotaExceeded)
    }
}
