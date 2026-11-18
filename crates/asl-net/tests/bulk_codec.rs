use std::io::ErrorKind;

use asl_net::codec::{
    BULK_PROTOCOL, BulkCodec, BulkOperation, BulkRequest, BulkResponse, BulkStatus,
};
use asl_types::ids::{Hash32, Id128};
use libp2p::{futures::io::Cursor, request_response::Codec};

fn request(operation: BulkOperation, chunk_index: u32) -> BulkRequest {
    BulkRequest {
        operation,
        request_id: Id128([1; 16]),
        content_id: Hash32([2; 32]),
        lease_id: Hash32([3; 32]),
        chunk_index,
    }
}

fn success_response(payload: Vec<u8>) -> BulkResponse {
    BulkResponse {
        request_id: Id128([4; 16]),
        status: BulkStatus::Success,
        payload,
    }
}

fn invalid_response(status: BulkStatus, payload: Vec<u8>) -> BulkResponse {
    BulkResponse {
        request_id: Id128([4; 16]),
        status,
        payload,
    }
}

#[tokio::test]
async fn request_uses_the_fixed_91_byte_protocol_layout() {
    let mut bytes = Vec::new();
    BulkCodec
        .write_request(
            &BULK_PROTOCOL,
            &mut bytes,
            request(BulkOperation::Chunk, 0x0102_0304),
        )
        .await
        .unwrap();

    assert_eq!(bytes.len(), 91);
    assert_eq!(&bytes[0..6], b"ASLB01");
    assert_eq!(bytes[6], 2);
    assert_eq!(&bytes[7..23], &[1; 16]);
    assert_eq!(&bytes[23..55], &[2; 32]);
    assert_eq!(&bytes[55..87], &[3; 32]);
    assert_eq!(&bytes[87..91], &[1, 2, 3, 4]);
    assert_eq!(
        BulkCodec
            .read_request(&BULK_PROTOCOL, &mut Cursor::new(bytes))
            .await
            .unwrap(),
        request(BulkOperation::Chunk, 0x0102_0304)
    );
}

#[tokio::test]
async fn response_uses_the_bounded_length_prefixed_layout() {
    let response = success_response(vec![0x5a; 58]);
    let mut bytes = Vec::new();
    BulkCodec
        .write_response(&BULK_PROTOCOL, &mut bytes, response.clone())
        .await
        .unwrap();

    assert_eq!(u32::from_be_bytes(bytes[..4].try_into().unwrap()), 85);
    assert_eq!(&bytes[4..10], b"ASLR01");
    assert_eq!(&bytes[10..26], &[4; 16]);
    assert_eq!(bytes[26], 0);
    assert_eq!(u32::from_be_bytes(bytes[27..31].try_into().unwrap()), 58);
    assert_eq!(&bytes[31..], &[0x5a; 58]);
    assert_eq!(
        BulkCodec
            .read_response(&BULK_PROTOCOL, &mut Cursor::new(bytes))
            .await
            .unwrap(),
        response
    );
}

#[tokio::test]
async fn request_operation_and_fixed_indices_are_validated() {
    for operation in [1_u8, 2, 3] {
        let mut bytes = vec![0; 91];
        bytes[..6].copy_from_slice(b"ASLB01");
        bytes[6] = operation;
        assert!(
            BulkCodec
                .read_request(&BULK_PROTOCOL, &mut Cursor::new(bytes))
                .await
                .is_ok()
        );
    }

    let mut unknown = vec![0; 91];
    unknown[..6].copy_from_slice(b"ASLB01");
    unknown[6] = 4;
    let mut nonzero_manifest_index = vec![0; 91];
    nonzero_manifest_index[..6].copy_from_slice(b"ASLB01");
    nonzero_manifest_index[6] = 1;
    nonzero_manifest_index[90] = 1;
    let mut nonzero_inline_index = nonzero_manifest_index.clone();
    nonzero_inline_index[6] = 3;
    for bytes in [unknown, nonzero_manifest_index, nonzero_inline_index] {
        assert_eq!(
            BulkCodec
                .read_request(&BULK_PROTOCOL, &mut Cursor::new(bytes))
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );
    }
    assert!(
        BulkCodec
            .write_request(
                &BULK_PROTOCOL,
                &mut Vec::new(),
                request(BulkOperation::Manifest, 1)
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn response_rejects_unknown_status_and_error_payloads() {
    for response in [
        invalid_response(BulkStatus::NotFound, vec![1]),
        invalid_response(BulkStatus::Busy, vec![1]),
        invalid_response(BulkStatus::Expired, vec![1]),
        invalid_response(BulkStatus::IntegrityFailed, vec![1]),
        invalid_response(BulkStatus::Cancelled, vec![1]),
    ] {
        assert!(
            BulkCodec
                .write_response(&BULK_PROTOCOL, &mut Vec::new(), response)
                .await
                .is_err()
        );
    }

    let mut unknown = vec![0; 27];
    unknown[0..6].copy_from_slice(b"ASLR01");
    unknown[22] = 6;
    assert_eq!(
        BulkCodec
            .read_response(
                &BULK_PROTOCOL,
                &mut Cursor::new([27_u32.to_be_bytes().to_vec(), unknown].concat())
            )
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidData
    );
}

#[tokio::test]
async fn oversized_or_malformed_lengths_are_rejected_before_payload_read() {
    let mut oversized_response = Cursor::new(2_097_238_u32.to_be_bytes());
    assert_eq!(
        BulkCodec
            .read_response(&BULK_PROTOCOL, &mut oversized_response)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidData
    );
    assert_eq!(oversized_response.position(), 4);

    let mut short_response = [26_u32.to_be_bytes().to_vec(), vec![0; 26]].concat();
    assert_eq!(
        BulkCodec
            .read_response(
                &BULK_PROTOCOL,
                &mut Cursor::new(std::mem::take(&mut short_response))
            )
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidData
    );

    let mut trailing = vec![0; 91];
    trailing.extend_from_slice(&[0]);
    assert_eq!(
        BulkCodec
            .read_request(&BULK_PROTOCOL, &mut Cursor::new(trailing))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidData
    );
}
