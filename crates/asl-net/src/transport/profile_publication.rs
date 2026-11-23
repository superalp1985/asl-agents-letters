use std::{
    io,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use asl_types::{
    ids::AgentId,
    record::{MAX_RECORD_LIFETIME_MS, RecordKind, RecordPayload, decode_record},
};
use libp2p::{
    PeerId,
    kad::{self, RecordKey},
};

use crate::dht::identity_record_key;

use super::{LocalTransport, MAX_DHT_PROVIDER_CANDIDATES, TransportEvent};

const READY_LIFETIME: Duration = Duration::from_secs(10);

pub(super) struct Publication {
    id: [u8; 16],
    agent: AgentId,
    stage: Stage,
}

enum Stage {
    Lookup(kad::QueryId),
    Ready {
        peers: Vec<PeerId>,
        deadline: Instant,
    },
    Put(kad::QueryId),
}

impl LocalTransport {
    pub fn prepare_profile_publication(&mut self, id: [u8; 16], agent: AgentId) -> io::Result<()> {
        if matches!(&self.profile_publication, Some(pending)
            if matches!(pending.stage, Stage::Ready { deadline, .. } if Instant::now() >= deadline))
        {
            self.profile_publication = None;
        }
        if id == [0; 16] {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if self.profile_publication.is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let key = profile_key(agent)?;
        let query = self
            .swarm
            .behaviour_mut()
            .dht
            .get_closest_peers(key.to_vec());
        self.profile_publication = Some(Publication {
            id,
            agent,
            stage: Stage::Lookup(query),
        });
        Ok(())
    }

    pub fn publish_prepared_profile(&mut self, id: [u8; 16], value: Vec<u8>) -> io::Result<()> {
        let pending = self
            .profile_publication
            .take_if(|pending| pending.id == id && matches!(pending.stage, Stage::Ready { .. }))
            .ok_or(io::ErrorKind::NotFound)?;
        let Stage::Ready { peers, deadline } = pending.stage else {
            unreachable!();
        };
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let peers = peers
            .into_iter()
            .filter(|peer| self.swarm.is_connected(peer))
            .collect::<Vec<_>>();
        if peers.is_empty() {
            return Err(io::ErrorKind::NotConnected.into());
        }
        let signed = decode_record(&value).map_err(|_| io::ErrorKind::InvalidInput)?;
        let RecordPayload::Profile(profile) = signed.record.payload else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        // Core authorized the exact signed payload before IPC. Net forwards a
        // typed reference only; it never resolves it or reads any file.
        if profile.agent_id != pending.agent {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let now_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(io::Error::other)?
                .as_millis(),
        )
        .map_err(io::Error::other)?;
        if now_ms < signed.record.issued_at_ms || now_ms >= signed.record.expires_at_ms {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let remaining = signed.record.expires_at_ms - now_ms;
        let record = kad::Record {
            key: profile_key(pending.agent)?,
            value,
            publisher: None,
            expires: Some(
                Instant::now() + Duration::from_millis(remaining.min(MAX_RECORD_LIFETIME_MS)),
            ),
        };
        // A single-stage PUT does not seed libp2p's autonomous local republication.
        let query = self.swarm.behaviour_mut().dht.put_record_to(
            record,
            peers.into_iter(),
            kad::Quorum::One,
        );
        self.profile_publication = Some(Publication {
            stage: Stage::Put(query),
            ..pending
        });
        Ok(())
    }

    pub fn cancel_profile_publication(&mut self, id: [u8; 16]) {
        if let Some(pending) = self.profile_publication.take_if(|pending| pending.id == id)
            && let Stage::Lookup(query) | Stage::Put(query) = pending.stage
            && let Some(mut query) = self.swarm.behaviour_mut().dht.query_mut(&query)
        {
            query.finish();
        }
    }

    pub(super) fn handle_profile_publication_progress(
        &mut self,
        event: &kad::Event,
    ) -> Option<TransportEvent> {
        let kad::Event::OutboundQueryProgressed {
            id, result, step, ..
        } = event
        else {
            return None;
        };
        let pending = self.profile_publication.as_mut()?;
        let operation_id = pending.id;
        let succeeded = match (&pending.stage, result) {
            (Stage::Lookup(query), kad::QueryResult::GetClosestPeers(result))
                if query == id && step.last =>
            {
                let peers = result
                    .as_ref()
                    .ok()
                    .into_iter()
                    .flat_map(|result| &result.peers)
                    .filter(|peer| self.swarm.is_connected(&peer.peer_id))
                    .take(MAX_DHT_PROVIDER_CANDIDATES)
                    .map(|peer| peer.peer_id)
                    .collect::<Vec<_>>();
                if peers.is_empty() {
                    self.profile_publication = None;
                    false
                } else {
                    pending.stage = Stage::Ready {
                        peers,
                        deadline: Instant::now() + READY_LIFETIME,
                    };
                    true
                }
            }
            (Stage::Put(query), kad::QueryResult::PutRecord(result))
                if query == id && step.last =>
            {
                self.profile_publication = None;
                result.is_ok()
            }
            _ => return None,
        };
        Some(TransportEvent::ProfilePublicationProgress {
            operation_id,
            succeeded,
        })
    }
}

fn profile_key(agent: AgentId) -> io::Result<RecordKey> {
    identity_record_key(agent, RecordKind::Profile).map_err(|_| io::ErrorKind::InvalidInput.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::TransportKind;
    use asl_types::{
        ids::{Hash32, Signature65},
        protocol::{ConceptRef, Profile},
        record::{SignedRecord, UnsignedRecord, encode_record},
    };
    use libp2p::{Multiaddr, identity::Keypair, kad::store::RecordStore};

    #[tokio::test]
    async fn profile_publication_over_tcp_needs_explicit_put_and_leaves_no_local_copy() {
        profile_exchange(false, None).await;
    }

    #[tokio::test]
    async fn profile_lookup_over_tcp_returns_candidate_not_automatic_local_storage() {
        profile_exchange(true, None).await;
    }

    #[tokio::test]
    async fn avatar_reference_survives_profile_put_and_get_over_tcp() {
        profile_exchange(true, Some(Hash32([9; 32]))).await;
    }

    async fn profile_exchange(serve: bool, avatar: Option<Hash32>) {
        let mut source = LocalTransport::new(Keypair::generate_ed25519()).unwrap();
        let mut receiver = LocalTransport::new(Keypair::generate_ed25519()).unwrap();
        receiver
            .listen(TransportKind::Tcp, "127.0.0.1:0".parse().unwrap())
            .unwrap();
        let address = tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                if let TransportEvent::Listening(_, address) = receiver.next_event().await.unwrap()
                {
                    break address;
                }
            }
        })
        .await
        .unwrap();
        let peer =
            asl_types::ids::PeerId::from_bytes(receiver.swarm.local_peer_id().to_bytes()).unwrap();
        let endpoint: Multiaddr = format!("/ip4/{}/tcp/{}", address.ip(), address.port())
            .parse()
            .unwrap();
        source.add_dht_peer(&peer, &endpoint).unwrap();
        source.dial(TransportKind::Tcp, address, &peer).unwrap();
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                tokio::select! {
                    event = source.next_event() => {
                        if matches!(event.unwrap(), TransportEvent::Connected { .. }) {
                            break;
                        }
                    }
                    event = receiver.next_event() => { event.unwrap(); }
                }
            }
        })
        .await
        .unwrap();
        let agent = AgentId([4; 32]);
        let key = profile_key(agent).unwrap();
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let value = encode_record(&SignedRecord {
            record: UnsignedRecord {
                payload: RecordPayload::Profile(Profile {
                    agent_id: agent,
                    sequence: 1,
                    capabilities: vec![ConceptRef::RUST],
                    avatar,
                }),
                sequence: 1,
                issued_at_ms: now_ms,
                expires_at_ms: now_ms + 60_000,
            },
            signature: Signature65([1; 65]),
        })
        .unwrap();

        tokio::time::timeout(Duration::from_secs(20), async {
            source.prepare_profile_publication([1; 16], agent).unwrap();
            let mut has_candidate = false;
            let mut has_ack = false;
            let mut submitted = false;
            while !has_ack || !has_candidate {
                tokio::select! {
                    event = source.next_event() => {
                        if let TransportEvent::ProfilePublicationProgress { operation_id, succeeded } = event.unwrap() {
                            assert!(succeeded);
                            match (operation_id, submitted) {
                                ([1, ..], false) => {
                                    source.cancel_profile_publication(operation_id);
                                    assert!(source.publish_prepared_profile(operation_id, value.clone()).is_err());
                                    source.prepare_profile_publication([2; 16], agent).unwrap();
                                }
                                ([2, ..], false) => {
                                    source.publish_prepared_profile(operation_id, value.clone()).unwrap();
                                    submitted = true;
                                }
                                ([2, ..], true) => has_ack = true,
                                _ => panic!("unexpected profile progress"),
                            }
                        }
                    }
                    event = receiver.next_event() => {
                        if let TransportEvent::DhtRecordCandidate { candidate_id, key: received_key, value: received } = event.unwrap() {
                            assert!(submitted);
                            assert_eq!(received_key.as_slice(), key.as_ref());
                            assert_eq!(received, value);
                            // Transport fixture only. Production decides after Core verifies the signature.
                            receiver.decide_dht_record(candidate_id, serve).unwrap();
                            has_candidate = true;
                        }
                    }
                }
            }
        }).await.unwrap();
        assert!(
            source
                .swarm
                .behaviour_mut()
                .dht
                .store_mut()
                .get(&key)
                .is_none()
        );
        assert_eq!(
            receiver
                .swarm
                .behaviour_mut()
                .dht
                .store_mut()
                .get(&key)
                .is_some(),
            serve
        );
        if serve {
            source
                .get_record(identity_record_key(agent, RecordKind::Profile).unwrap())
                .unwrap();
            tokio::time::timeout(Duration::from_secs(8), async {
                loop {
                    tokio::select! {
                        event = source.next_event() => {
                            if let TransportEvent::DhtRecordCandidate {candidate_id,key: found,value: received} = event.unwrap() {
                                assert_eq!(found.as_slice(), key.as_ref());
                                assert_eq!(received, value);
                                source.decide_dht_record(candidate_id,false).unwrap();
                                break;
                            }
                        }
                        event = receiver.next_event() => { event.unwrap(); }
                    }
                }
            }).await.unwrap();
            assert!(
                source
                    .swarm
                    .behaviour_mut()
                    .dht
                    .store_mut()
                    .get(&key)
                    .is_none()
            );
        }
    }
}
