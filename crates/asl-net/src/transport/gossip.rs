use super::*;
use libp2p::gossipsub::{
    self, IdentTopic, MaxCountSubscriptionFilter, MessageId, TopicHash, TopicSubscriptionFilter,
    ValidationMode,
};

pub const MAX_GOSSIP_PAYLOAD_BYTES: usize = 64 * 1024;
pub const MAX_GOSSIP_SUBSCRIPTIONS: usize = 32;

const MAX_GOSSIP_RPC_BYTES: usize = 64 * 1024;
const MAX_GOSSIP_SUBSCRIPTIONS_PER_RPC: usize = 8;
const GOSSIP_TOPIC_PREFIX: &str = "asl/gossip/v1/";

/// A gossipsub topic derived only from a 32-byte ASL room key.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct GossipTopic([u8; 32]);

impl GossipTopic {
    pub const fn new(key: [u8; 32]) -> Self {
        Self(key)
    }

    pub const fn key(self) -> [u8; 32] {
        self.0
    }

    fn from_hash(hash: &TopicHash) -> Option<Self> {
        let encoded = hash.as_str().strip_prefix(GOSSIP_TOPIC_PREFIX)?;
        if encoded.len() != 64 {
            return None;
        }

        let bytes = encoded.as_bytes();
        let mut key = [0; 32];
        for (index, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
            key[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
        }
        Some(Self(key))
    }

    fn ident_topic(self) -> IdentTopic {
        IdentTopic::new(self.to_string())
    }
}

impl From<[u8; 32]> for GossipTopic {
    fn from(key: [u8; 32]) -> Self {
        Self::new(key)
    }
}

impl std::fmt::Display for GossipTopic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(GOSSIP_TOPIC_PREFIX)?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A payload delivered by bounded ASL gossipsub.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GossipMessage {
    pub topic: GossipTopic,
    pub propagation_source: PeerId,
    pub message_id: Vec<u8>,
    pub data: Vec<u8>,
}

#[derive(Default)]
pub(super) struct AslTopicFilter;

impl TopicSubscriptionFilter for AslTopicFilter {
    fn can_subscribe(&mut self, topic_hash: &TopicHash) -> bool {
        GossipTopic::from_hash(topic_hash).is_some()
    }
}

pub(super) type GossipBehaviour =
    gossipsub::Behaviour<gossipsub::IdentityTransform, MaxCountSubscriptionFilter<AslTopicFilter>>;

fn bounded_config() -> io::Result<gossipsub::Config> {
    let mut config = gossipsub::ConfigBuilder::default();
    config
        .protocol_id_prefix("/asl/gossip")
        .history_length(3)
        .history_gossip(1)
        .mesh_n(4)
        .mesh_n_low(2)
        .mesh_n_high(8)
        .mesh_outbound_min(1)
        .gossip_lazy(2)
        .retain_scores(2)
        .max_transmit_size(MAX_GOSSIP_RPC_BYTES)
        .max_control_message_size(4 * 1024)
        .max_publish_messages(4)
        .max_control_messages_sent(64)
        .max_ihave_messages_heartbeat(2)
        .validation_mode(ValidationMode::Anonymous)
        .allow_self_origin(false)
        .flood_publish(true)
        .message_id_fn(|message| {
            let mut hasher = blake3::Hasher::new();
            hasher.update(message.topic.as_str().as_bytes());
            hasher.update(&message.data);
            MessageId::new(hasher.finalize().as_bytes())
        });
    config.build().map_err(io::Error::other)
}

pub(super) fn new_behaviour() -> io::Result<GossipBehaviour> {
    let config = bounded_config()?;
    let filter = MaxCountSubscriptionFilter {
        filter: AslTopicFilter,
        max_subscribed_topics: MAX_GOSSIP_SUBSCRIPTIONS,
        max_subscriptions_per_request: MAX_GOSSIP_SUBSCRIPTIONS_PER_RPC,
    };

    gossipsub::Behaviour::new_with_subscription_filter(
        gossipsub::MessageAuthenticity::Anonymous,
        config,
        filter,
    )
    .map_err(io::Error::other)
}

impl LocalTransport {
    pub fn subscribe_gossip(&mut self, topic: GossipTopic) -> io::Result<bool> {
        if !self.gossip_subscriptions.contains(&topic)
            && self.gossip_subscriptions.len() >= MAX_GOSSIP_SUBSCRIPTIONS
        {
            return Err(io::Error::other("gossip subscription limit reached"));
        }
        let subscribed = self
            .swarm
            .behaviour_mut()
            .gossip
            .subscribe(&topic.ident_topic())
            .map_err(gossip_subscription_error)?;
        if subscribed {
            self.gossip_subscriptions.insert(topic);
        }
        Ok(subscribed)
    }

    pub fn unsubscribe_gossip(&mut self, topic: GossipTopic) -> bool {
        let unsubscribed = self
            .swarm
            .behaviour_mut()
            .gossip
            .unsubscribe(&topic.ident_topic());
        if unsubscribed {
            self.gossip_subscriptions.remove(&topic);
        }
        unsubscribed
    }

    pub fn publish_gossip(&mut self, topic: GossipTopic, data: Vec<u8>) -> io::Result<Vec<u8>> {
        if !self.gossip_subscriptions.contains(&topic) {
            return Err(io::ErrorKind::NotConnected.into());
        }
        if data.len() > MAX_GOSSIP_PAYLOAD_BYTES {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.swarm
            .behaviour_mut()
            .gossip
            .publish(topic.ident_topic(), data)
            .map(|message_id| message_id.0)
            .map_err(gossip_publish_error)
    }

    pub(super) fn handle_gossip(&self, event: gossipsub::Event) -> Option<TransportEvent> {
        let gossipsub::Event::Message {
            propagation_source,
            message_id,
            message,
        } = event
        else {
            return None;
        };
        if message.data.len() > MAX_GOSSIP_PAYLOAD_BYTES {
            return None;
        }
        let topic = GossipTopic::from_hash(&message.topic)?;
        if !self.gossip_subscriptions.contains(&topic) {
            return None;
        }
        Some(TransportEvent::GossipMessage(GossipMessage {
            topic,
            propagation_source: device_peer(propagation_source).ok()?,
            message_id: message_id.0,
            data: message.data,
        }))
    }
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn gossip_subscription_error(error: gossipsub::SubscriptionError) -> io::Error {
    match error {
        gossipsub::SubscriptionError::NotAllowed => io::ErrorKind::PermissionDenied.into(),
        gossipsub::SubscriptionError::PublishError(error) => gossip_publish_error(error),
    }
}

fn gossip_publish_error(error: gossipsub::PublishError) -> io::Error {
    match error {
        gossipsub::PublishError::Duplicate => io::ErrorKind::AlreadyExists.into(),
        gossipsub::PublishError::NoPeersSubscribedToTopic => io::ErrorKind::NotConnected.into(),
        gossipsub::PublishError::MessageTooLarge => io::ErrorKind::InvalidInput.into(),
        gossipsub::PublishError::AllQueuesFull(_) => io::ErrorKind::WouldBlock.into(),
        gossipsub::PublishError::SigningError(_) | gossipsub::PublishError::TransformFailed(_) => {
            io::Error::other(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::{Ipv4Addr, SocketAddrV4},
        time::Duration,
    };
    use tokio::time::{Instant, timeout_at};

    #[test]
    fn topics_round_trip_only_for_fixed_prefix_and_key_length() {
        let topic = GossipTopic::new([0xab; 32]);
        let hash = topic.ident_topic().hash();
        assert_eq!(GossipTopic::from_hash(&hash), Some(topic));
        assert_eq!(
            topic.to_string(),
            "asl/gossip/v1/abababababababababababababababababababababababababababababababab"
        );

        assert_eq!(
            GossipTopic::from_hash(&TopicHash::from_raw("chat/room")),
            None
        );
        assert_eq!(
            GossipTopic::from_hash(&TopicHash::from_raw(format!("{GOSSIP_TOPIC_PREFIX}abcd"))),
            None
        );
        assert_eq!(
            GossipTopic::from_hash(&TopicHash::from_raw(format!(
                "{GOSSIP_TOPIC_PREFIX}{}",
                "zz".repeat(32)
            ))),
            None
        );
    }

    #[test]
    fn config_is_bounded() {
        let config = bounded_config().unwrap();
        assert_eq!(config.max_transmit_size(), MAX_GOSSIP_RPC_BYTES);
        assert!(config.mesh_n_high() <= 8);
        assert_eq!(config.max_ihave_messages_heartbeat(), 2);
        assert_eq!(config.max_publish_messages(), 4);
    }

    #[tokio::test]
    async fn two_local_transports_deliver_anonymous_gossip() {
        for kind in [TransportKind::Tcp, TransportKind::Quic] {
            let listener_identity = Keypair::generate_ed25519();
            let listener_peer = device_peer(listener_identity.public().to_peer_id()).unwrap();
            let mut listener = LocalTransport::new(listener_identity).unwrap();
            listener
                .listen(kind, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into())
                .unwrap();
            let endpoint = loop {
                match listener.next_event().await.unwrap() {
                    TransportEvent::Listening(observed, endpoint) if observed == kind => {
                        break endpoint;
                    }
                    _ => continue,
                }
            };

            let dialer_identity = Keypair::generate_ed25519();
            let dialer_peer = device_peer(dialer_identity.public().to_peer_id()).unwrap();
            let mut dialer = LocalTransport::new(dialer_identity).unwrap();
            dialer.dial(kind, endpoint, &listener_peer).unwrap();
            let (dialer_connected, listener_connected) =
                tokio::join!(dialer.next_event(), listener.next_event());
            assert!(matches!(
                dialer_connected.unwrap(),
                TransportEvent::Connected { connection } if connection.peer_id() == &listener_peer
            ));
            assert!(matches!(
                listener_connected.unwrap(),
                TransportEvent::Connected { connection } if connection.peer_id() == &dialer_peer
            ));

            let topic = GossipTopic::new([0x42; 32]);
            assert!(dialer.subscribe_gossip(topic).unwrap());
            assert!(listener.subscribe_gossip(topic).unwrap());

            let payload = b"bounded anonymous gossip".to_vec();
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                match dialer.publish_gossip(topic, payload.clone()) {
                    Ok(_) => break,
                    Err(error)
                        if error.kind() == io::ErrorKind::NotConnected
                            && Instant::now() < deadline =>
                    {
                        drive_for(&mut dialer, Duration::from_millis(100)).await;
                        drive_for(&mut listener, Duration::from_millis(100)).await;
                    }
                    Err(error) => panic!("gossip publish failed: {error}"),
                }
            }

            drive_for(&mut dialer, Duration::from_millis(100)).await;
            loop {
                let event = timeout_at(deadline, listener.next_event())
                    .await
                    .expect("gossip delivery timed out")
                    .unwrap();
                let TransportEvent::GossipMessage(message) = event else {
                    continue;
                };
                assert_eq!(message.topic, topic);
                assert_eq!(message.propagation_source, dialer_peer);
                assert_eq!(message.data, payload);
                break;
            }
        }
    }

    async fn drive_for(transport: &mut LocalTransport, duration: Duration) {
        let deadline = Instant::now() + duration;
        while timeout_at(deadline, transport.next_event()).await.is_ok() {}
    }
}
