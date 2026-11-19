//! One-shot, explicitly requested inline payload verification.

use std::collections::HashMap;

use asl_types::{error::AslError, ids::Hash32};

pub const MAX_INLINE_BYTES: usize = 32 * 1024;
pub const MAX_PENDING_INLINE_REQUESTS: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedInline {
    pub request_id: [u8; 16],
    pub content_id: Hash32,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
struct Expectation {
    content_id: Hash32,
    expected_hash: [u8; 32],
    expected_length: usize,
}

#[derive(Default)]
pub struct InlineRequests {
    pending: HashMap<[u8; 16], Expectation>,
}

impl InlineRequests {
    /// Register only after the local task explicitly requested this content.
    pub fn register(
        &mut self,
        request_id: [u8; 16],
        content_id: Hash32,
        expected_hash: [u8; 32],
        expected_length: usize,
    ) -> Result<(), AslError> {
        if request_id == [0; 16]
            || expected_length > MAX_INLINE_BYTES
            || self.pending.len() >= MAX_PENDING_INLINE_REQUESTS
            || self.pending.contains_key(&request_id)
        {
            return Err(AslError::InvalidMessage);
        }
        self.pending.insert(
            request_id,
            Expectation {
                content_id,
                expected_hash,
                expected_length,
            },
        );
        Ok(())
    }

    /// Consumes the request even when its response is invalid, preventing replay.
    pub fn accept(
        &mut self,
        request_id: [u8; 16],
        content_id: Hash32,
        bytes: Vec<u8>,
    ) -> Result<VerifiedInline, AslError> {
        let expected = self.pending.remove(&request_id).ok_or(AslError::NotFound)?;
        if content_id != expected.content_id
            || bytes.len() != expected.expected_length
            || *blake3::hash(&bytes).as_bytes() != expected.expected_hash
        {
            return Err(AslError::InvalidMessage);
        }
        Ok(VerifiedInline {
            request_id,
            content_id,
            bytes,
        })
    }

    pub fn cancel(&mut self, request_id: &[u8; 16]) -> bool {
        self.pending.remove(request_id).is_some()
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn content_id() -> Hash32 {
        Hash32([9; 32])
    }

    fn register(registry: &mut InlineRequests, id: [u8; 16], bytes: &[u8]) {
        registry
            .register(
                id,
                content_id(),
                *blake3::hash(bytes).as_bytes(),
                bytes.len(),
            )
            .unwrap();
    }

    #[test]
    fn only_requested_matching_inline_bytes_are_returned_once() {
        let bytes = b"structured inline payload".to_vec();
        let mut requests = InlineRequests::default();
        register(&mut requests, [1; 16], &bytes);

        let verified = requests
            .accept([1; 16], content_id(), bytes.clone())
            .unwrap();
        assert_eq!(verified.bytes, bytes);
        assert_eq!(requests.pending_count(), 0);
        assert!(matches!(
            requests.accept([1; 16], content_id(), verified.bytes),
            Err(AslError::NotFound)
        ));
    }

    #[test]
    fn unsolicited_mismatched_and_oversized_payloads_are_rejected() {
        let mut requests = InlineRequests::default();
        assert!(matches!(
            requests.accept([8; 16], content_id(), b"unsolicited".to_vec()),
            Err(AslError::NotFound)
        ));

        register(&mut requests, [2; 16], b"expected");
        assert!(matches!(
            requests.accept([2; 16], Hash32([8; 32]), b"expected".to_vec()),
            Err(AslError::InvalidMessage)
        ));
        assert_eq!(requests.pending_count(), 0);

        assert!(
            requests
                .register([3; 16], content_id(), [0; 32], MAX_INLINE_BYTES + 1)
                .is_err()
        );
    }

    #[test]
    fn pending_requests_are_bounded_and_cancellable() {
        let mut requests = InlineRequests::default();
        for index in 1..=MAX_PENDING_INLINE_REQUESTS {
            requests
                .register([index as u8; 16], content_id(), [0; 32], 0)
                .unwrap();
        }
        assert!(
            requests
                .register([99; 16], content_id(), [0; 32], 0)
                .is_err()
        );
        assert!(requests.cancel(&[1; 16]));
        assert!(!requests.cancel(&[1; 16]));
        assert_eq!(requests.pending_count(), MAX_PENDING_INLINE_REQUESTS - 1);
    }
}
