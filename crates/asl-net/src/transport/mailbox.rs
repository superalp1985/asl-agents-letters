use std::{
    io,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use libp2p::kad::{self, Quorum, Record, RecordKey};

use crate::mailbox::{MAX_MAILBOX_RECORD_LIFETIME_MS, MailboxRecord};

use super::{LocalTransport, TransportEvent};

const MAX_PENDING_MAILBOX_PUTS: usize = 16;

impl LocalTransport {
    pub fn put_mailbox_record(&mut self, record: &MailboxRecord) -> io::Result<kad::QueryId> {
        if self.pending_mailbox_puts.len() >= MAX_PENDING_MAILBOX_PUTS {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let now_ms = unix_time_millis()?;
        if record.expires_at_ms <= now_ms {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if record.expires_at_ms - now_ms > MAX_MAILBOX_RECORD_LIFETIME_MS {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        record
            .validate_at(now_ms)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;

        let key = record
            .record_key()
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let value = record
            .encode()
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let dht_record = Record {
            key: key.clone(),
            value,
            publisher: None,
            expires: Some(Instant::now() + Duration::from_millis(record.expires_at_ms - now_ms)),
        };
        let query_id = self
            .swarm
            .behaviour_mut()
            .dht
            .put_record(dht_record, Quorum::One)
            .map_err(|_| io::Error::other("DHT mailbox record capacity reached"))?;
        self.pending_mailbox_puts.insert(query_id, key);
        Ok(query_id)
    }

    pub(super) fn handle_mailbox_put_progress(
        &mut self,
        event: &kad::Event,
    ) -> Option<TransportEvent> {
        let kad::Event::OutboundQueryProgressed {
            id,
            result: kad::QueryResult::PutRecord(result),
            step,
            ..
        } = event
        else {
            return None;
        };
        if !step.last {
            return None;
        }
        let key: RecordKey = self.pending_mailbox_puts.remove(id)?;
        self.swarm.behaviour_mut().dht.remove_record(&key);
        Some(TransportEvent::MailboxRecordPut {
            query_id: *id,
            succeeded: result.is_ok(),
        })
    }
}

fn unix_time_millis() -> io::Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_millis(),
    )
    .map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::{Multiaddr, identity::Keypair};

    use super::super::TransportKind;

    fn record() -> MailboxRecord {
        let now_ms = unix_time_millis().unwrap();
        MailboxRecord {
            recipient_id: [1; 32],
            sender_id: [2; 32],
            topic_id: [3; 32],
            mailbox_id: [4; 32],
            shard_id: [5; 32],
            epoch: 1,
            shard_index: 0,
            shard_count: 1,
            expires_at_ms: now_ms + 60_000,
            ciphertext: b"opaque-ciphertext".to_vec(),
        }
    }

    #[tokio::test]
    async fn put_mailbox_record_tracks_query_completion() {
        let mut transport = LocalTransport::new(Keypair::generate_ed25519()).unwrap();
        let query_id = transport.put_mailbox_record(&record()).unwrap();
        let event = tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                if let TransportEvent::MailboxRecordPut {
                    query_id: completed,
                    ..
                } = transport.next_event().await.unwrap()
                {
                    break completed;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(event, query_id);
        assert!(transport.pending_mailbox_puts.is_empty());
    }

    #[tokio::test]
    async fn mailbox_record_put_and_raw_get_use_the_existing_dht_candidate_path() {
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
        let receiver_peer =
            asl_types::ids::PeerId::from_bytes(receiver.swarm.local_peer_id().to_bytes()).unwrap();
        let endpoint: Multiaddr = format!("/ip4/{}/tcp/{}", address.ip(), address.port())
            .parse()
            .unwrap();
        source.add_dht_peer(&receiver_peer, &endpoint).unwrap();
        source
            .dial(TransportKind::Tcp, address, &receiver_peer)
            .unwrap();
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

        let mailbox = record();
        let key = mailbox.record_key().unwrap();
        let value = mailbox.encode().unwrap();
        let put_query = source.put_mailbox_record(&mailbox).unwrap();
        let (mut put_completed, mut receiver_stored) = (false, false);
        tokio::time::timeout(Duration::from_secs(25), async {
            while !put_completed || !receiver_stored {
                tokio::select! {
                    event = source.next_event() => {
                        if let TransportEvent::MailboxRecordPut { query_id, succeeded } = event.unwrap() {
                            assert_eq!(query_id, put_query);
                            assert!(succeeded);
                            put_completed = true;
                        }
                    }
                    event = receiver.next_event() => {
                        if let TransportEvent::DhtRecordCandidate { candidate_id, key: received_key, value: received } = event.unwrap() {
                            assert_eq!(received_key.as_slice(), key.as_ref());
                            assert_eq!(received, value);
                            receiver.decide_dht_record(candidate_id, true).unwrap();
                            receiver_stored = true;
                        }
                    }
                }
            }
        })
        .await
        .unwrap();

        source.get_record(key.clone()).unwrap();
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                tokio::select! {
                    event = source.next_event() => {
                        if let TransportEvent::DhtRecordCandidate { candidate_id, key: received_key, value: received } = event.unwrap() {
                            assert_eq!(received_key.as_slice(), key.as_ref());
                            assert_eq!(received, value);
                            source.decide_dht_record(candidate_id, false).unwrap();
                            break;
                        }
                    }
                    event = receiver.next_event() => { event.unwrap(); }
                }
            }
        })
        .await
        .unwrap();
    }
}
