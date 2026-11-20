//! ASL authentication for OpenMLS leaves. Neither a valid MLS signature nor
//! a verified ASL credential grants membership on its own.

use asl_types::{
    error::AslError,
    ids::{Hash32, Signature65},
    protocol::DeviceCertificate,
    record::RecordPayload,
};
use curve25519_dalek::edwards::CompressedEdwardsY;
use openmls::prelude::{BasicCredential, CredentialType, CredentialWithKey};
use openmls_basic_credential::SignatureKeyPair;

use crate::{
    chain::IdentityResolver,
    identity::{AgentIdentity, verify_device_certificate, verify_root_signature},
};

use super::{RecordHistory, admission::transport_ed25519_key, verify_record};

pub use asl_groups::membership::GROUP_CIPHERSUITE;
const DOMAIN: &[u8] = b"ASL-MLS-LEAF-v1\0";
// v1 device certificate with a PeerId of at most 128 bytes.
const MAX_CERTIFICATE_BYTES: usize = 272;

/// Generate a fresh signer rather than importing any transport key. Current
/// chain admission still has to be checked before using the leaf in a room.
pub fn issue_group_credential(
    root: &AgentIdentity,
    wire_room: Hash32,
    certificate: &DeviceCertificate,
    now_ms: u64,
) -> Result<(SignatureKeyPair, CredentialWithKey), AslError> {
    verify_device_certificate(
        certificate,
        root.agent_id(),
        &certificate.peer_id,
        root.controller_address(),
        1,
        now_ms,
    )?;
    let signer = SignatureKeyPair::new(GROUP_CIPHERSUITE.signature_algorithm())
        .map_err(|_| AslError::InvalidIdentity)?;
    let public = signer.to_public_vec();
    let body = certificate.to_canonical_cbor()?;
    let transcript = signing_bytes(wire_room, &public, certificate, &body)?;
    let signature = root.sign_domain_message(&transcript)?;
    let mut identity = Vec::with_capacity(Signature65::LENGTH + body.len());
    identity.extend_from_slice(signature.as_bytes());
    identity.extend_from_slice(&body);
    Ok((
        signer,
        CredentialWithKey {
            credential: BasicCredential::new(identity).into(),
            signature_key: public.into(),
        },
    ))
}

/// Verify a leaf of a candidate tree, using the expected Agent's local
/// history and a directory checked against the current chain state.
/// This is not proof of possession: callers still need OpenMLS signature
/// validation and must enforce the room roster and membership policy.
pub fn verify_group_leaf(
    wire_room: Hash32,
    leaf: &CredentialWithKey,
    signed_directory: &[u8],
    history: &mut RecordHistory,
    resolver: &mut dyn IdentityResolver,
    now_ms: u64,
) -> Result<DeviceCertificate, AslError> {
    let (signature, body) = credential_parts(leaf)?;
    let certificate = DeviceCertificate::from_canonical_cbor(body)?;
    let verified = verify_record(signed_directory, certificate.agent_id, now_ms, resolver)?;
    let RecordPayload::DeviceDirectory(directory) = &verified.signed().record.payload else {
        return Err(AslError::InvalidDeviceCertificate);
    };
    if !directory.devices.contains(&certificate) {
        return Err(AslError::InvalidDeviceCertificate);
    }
    let transcript = signing_bytes(wire_room, leaf.signature_key.as_slice(), &certificate, body)?;
    verify_root_signature(&transcript, signature, verified.registry_state.controller)?;
    history.observe(&verified)?;
    Ok(certificate)
}

pub(super) fn verify_binding(
    wire_room: Hash32,
    leaf: &CredentialWithKey,
    admitted: &DeviceCertificate,
    controller: [u8; 20],
) -> Result<(), AslError> {
    let (signature, body) = credential_parts(leaf)?;
    if body != admitted.to_canonical_cbor()? {
        return Err(AslError::InvalidDeviceCertificate);
    }
    let transcript = signing_bytes(wire_room, leaf.signature_key.as_slice(), admitted, body)?;
    verify_root_signature(&transcript, signature, controller)
}

fn credential_parts(leaf: &CredentialWithKey) -> Result<(Signature65, &[u8]), AslError> {
    let bytes = leaf.credential.serialized_content();
    if leaf.credential.credential_type() != CredentialType::Basic
        || !(Signature65::LENGTH + 1..=Signature65::LENGTH + MAX_CERTIFICATE_BYTES)
            .contains(&bytes.len())
    {
        return Err(AslError::InvalidDeviceCertificate);
    }
    let (signature, body) = bytes
        .split_first_chunk::<{ Signature65::LENGTH }>()
        .ok_or(AslError::InvalidDeviceCertificate)?;
    Ok((Signature65(*signature), body))
}

fn signing_bytes(
    wire_room: Hash32,
    public: &[u8],
    certificate: &DeviceCertificate,
    certificate_cbor: &[u8],
) -> Result<Vec<u8>, AslError> {
    let transport_key = transport_ed25519_key(&certificate.peer_id)?;
    let key = CompressedEdwardsY(
        public
            .try_into()
            .map_err(|_| AslError::InvalidDeviceCertificate)?,
    );
    if wire_room.0 == [0; 32]
        || key.0 == transport_key
        || !key
            .decompress()
            .is_some_and(|point| point.compress() == key && !point.is_small_order())
    {
        return Err(AslError::InvalidDeviceCertificate);
    }
    let mut bytes =
        Vec::with_capacity(DOMAIN.len() + Hash32::LENGTH + public.len() + certificate_cbor.len());
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(wire_room.as_bytes());
    bytes.extend_from_slice(public);
    bytes.extend_from_slice(certificate_cbor);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use asl_types::protocol::{WireFrame, decode_control};

    #[test]
    fn transcript_matches_fixed_device_certificate_and_public_key() {
        let bytes: Vec<u8> = include_str!("../../../../schemas/vectors/hello-v1.hex")
            .split_ascii_whitespace()
            .map(|byte| u8::from_str_radix(byte, 16).unwrap())
            .collect();
        let WireFrame::Hello(hello) = decode_control(&bytes).unwrap() else {
            panic!("expected frozen Hello vector");
        };
        // Exact CBOR span of key 5 from the frozen Hello vector.
        let certificate_bytes = &bytes[100..255];
        let certificate = hello.device_certificate;
        assert_eq!(certificate.to_canonical_cbor().unwrap(), certificate_bytes);
        let public = alloy_primitives::hex::decode(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        )
        .unwrap();
        let room = Hash32([7; 32]);
        let expected = [
            b"ASL-MLS-LEAF-v1\0".as_slice(),
            &[7; 32],
            &public,
            certificate_bytes,
        ]
        .concat();
        assert_eq!(
            signing_bytes(room, &public, &certificate, certificate_bytes).unwrap(),
            expected
        );
        for key in [
            [0; 32],
            transport_ed25519_key(&certificate.peer_id).unwrap(),
        ] {
            assert!(signing_bytes(room, &key, &certificate, certificate_bytes).is_err());
        }
    }
}
