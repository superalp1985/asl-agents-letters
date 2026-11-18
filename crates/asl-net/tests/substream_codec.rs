use std::io::ErrorKind;

use asl_net::codec::{CONTROL_PROTOCOL, ControlCodec, IDENTITY_PROOF_PROTOCOL, IdentityProofCodec};
use asl_types::protocol::{WireFrame, decode_control, decode_frame};
use libp2p::{futures::io::Cursor, request_response::Codec};

fn fixture(hex: &str) -> Vec<u8> {
    hex.split_ascii_whitespace()
        .map(|byte| u8::from_str_radix(byte, 16).unwrap())
        .collect()
}

fn prefixed(payload: &[u8]) -> Vec<u8> {
    let mut bytes = u32::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
    bytes.extend_from_slice(payload);
    bytes
}

#[tokio::test]
async fn control_matches_the_fixed_ack_vector_with_a_big_endian_prefix() {
    let payload = fixture(include_str!("../../../schemas/vectors/ack-v1.hex"));
    let frame = decode_control(&payload).unwrap();
    let mut written = Vec::new();
    ControlCodec
        .write_request(&CONTROL_PROTOCOL, &mut written, frame.clone())
        .await
        .unwrap();
    assert_eq!(&written[..4], &[0, 0, 0, 41]);
    assert_eq!(&written[4..], payload);
    assert_eq!(
        ControlCodec
            .read_request(&CONTROL_PROTOCOL, &mut Cursor::new(written))
            .await
            .unwrap(),
        frame
    );

    let mut written = Vec::new();
    ControlCodec
        .write_response(&CONTROL_PROTOCOL, &mut written, frame.clone())
        .await
        .unwrap();
    assert_eq!(written, prefixed(&payload));
    assert_eq!(
        ControlCodec
            .read_response(&CONTROL_PROTOCOL, &mut Cursor::new(written))
            .await
            .unwrap(),
        frame
    );
}

#[tokio::test]
async fn identity_proof_matches_the_fixed_request_and_response_vectors() {
    let request_bytes = fixture(include_str!(
        "../../../schemas/vectors/identity-proof-request-v1.hex"
    ));
    let response_bytes = fixture(include_str!(
        "../../../schemas/vectors/identity-proof-v1.hex"
    ));
    let WireFrame::IdentityProofRequest(request) = decode_frame(&request_bytes).unwrap() else {
        panic!("wrong request fixture");
    };
    let WireFrame::IdentityProof(response) = decode_frame(&response_bytes).unwrap() else {
        panic!("wrong response fixture");
    };

    let mut written = Vec::new();
    IdentityProofCodec
        .write_request(&IDENTITY_PROOF_PROTOCOL, &mut written, request.clone())
        .await
        .unwrap();
    assert_eq!(written, prefixed(&request_bytes));
    assert_eq!(
        IdentityProofCodec
            .read_request(&IDENTITY_PROOF_PROTOCOL, &mut Cursor::new(written))
            .await
            .unwrap(),
        request
    );

    let mut written = Vec::new();
    IdentityProofCodec
        .write_response(&IDENTITY_PROOF_PROTOCOL, &mut written, response.clone())
        .await
        .unwrap();
    assert_eq!(written, prefixed(&response_bytes));
    assert_eq!(
        IdentityProofCodec
            .read_response(&IDENTITY_PROOF_PROTOCOL, &mut Cursor::new(written))
            .await
            .unwrap(),
        response
    );
}

#[tokio::test]
async fn channel_limits_reject_the_header_without_reading_a_body() {
    let mut oversized_control = Cursor::new(65_537_u32.to_be_bytes());
    let mut oversized_request = Cursor::new(94_u32.to_be_bytes());
    let mut oversized_proof = Cursor::new(262_145_u32.to_be_bytes());
    assert_eq!(
        ControlCodec
            .read_request(&CONTROL_PROTOCOL, &mut oversized_control)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidData
    );
    assert_eq!(
        IdentityProofCodec
            .read_request(&IDENTITY_PROOF_PROTOCOL, &mut oversized_request)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidData
    );
    assert_eq!(
        IdentityProofCodec
            .read_response(&IDENTITY_PROOF_PROTOCOL, &mut oversized_proof)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidData
    );
    assert_eq!(oversized_control.position(), 4);
    assert_eq!(oversized_request.position(), 4);
    assert_eq!(oversized_proof.position(), 4);
}

#[tokio::test]
async fn incomplete_or_extra_substream_data_never_yields_a_control_frame() {
    let payload = fixture(include_str!("../../../schemas/vectors/ack-v1.hex"));
    let valid = prefixed(&payload);
    for truncated in [&valid[..3], &valid[..valid.len() - 1]] {
        assert_eq!(
            ControlCodec
                .read_request(&CONTROL_PROTOCOL, &mut Cursor::new(truncated))
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::UnexpectedEof
        );
    }
    let mut repeated = valid.clone();
    repeated.extend_from_slice(&valid);
    assert_eq!(
        ControlCodec
            .read_request(&CONTROL_PROTOCOL, &mut Cursor::new(repeated))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidData
    );
}

#[tokio::test]
async fn frames_cannot_cross_protocols_or_swap_proof_directions() {
    let ack = fixture(include_str!("../../../schemas/vectors/ack-v1.hex"));
    let request = fixture(include_str!(
        "../../../schemas/vectors/identity-proof-request-v1.hex"
    ));
    assert!(
        ControlCodec
            .read_request(&CONTROL_PROTOCOL, &mut Cursor::new(prefixed(&request)))
            .await
            .is_err()
    );
    assert!(
        IdentityProofCodec
            .read_request(&IDENTITY_PROOF_PROTOCOL, &mut Cursor::new(prefixed(&ack)))
            .await
            .is_err()
    );
    assert!(
        IdentityProofCodec
            .read_response(
                &IDENTITY_PROOF_PROTOCOL,
                &mut Cursor::new(prefixed(&request)),
            )
            .await
            .is_err()
    );
    assert!(
        ControlCodec
            .read_request(&IDENTITY_PROOF_PROTOCOL, &mut Cursor::new(prefixed(&ack)))
            .await
            .is_err()
    );
    let mut written = Vec::new();
    assert!(
        ControlCodec
            .write_response(
                &CONTROL_PROTOCOL,
                &mut written,
                decode_frame(&request).unwrap(),
            )
            .await
            .is_err()
    );
    assert!(written.is_empty());
}
