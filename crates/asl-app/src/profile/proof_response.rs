use asl_types::{
    error::AslError,
    protocol::{Hello, IdentityProof, IdentityProofRequest, WireFrame, encode_frame},
    record::RecordPayload,
};

use crate::chain::{DurableIdentityResolver, identity_proof_to_wire};

use super::{DeviceAdmissionError, verify_record};

/// Responds using only locally configured identity material and a cached proof.
/// An incoming request cannot initiate RPC acquisition or select another identity.
pub fn serve_local_identity_proof(
    local_hello: &Hello,
    signed_directory: &[u8],
    request: &IdentityProofRequest,
    resolver: &mut DurableIdentityResolver,
    now_ms: u64,
) -> Result<Option<IdentityProof>, DeviceAdmissionError> {
    if request.agent_id != local_hello.agent_id {
        return Ok(None);
    }
    let Some(proof) = resolver
        .cached_identity_proof(request, now_ms / 1_000)
        .map_err(DeviceAdmissionError::Chain)?
    else {
        return Ok(None);
    };
    let record = verify_record(signed_directory, local_hello.agent_id, now_ms, resolver)
        .map_err(DeviceAdmissionError::Session)?;
    let RecordPayload::DeviceDirectory(directory) = &record.signed().record.payload else {
        return Err(DeviceAdmissionError::Session(
            AslError::InvalidDeviceCertificate,
        ));
    };
    if local_hello.peer_id != local_hello.device_certificate.peer_id
        || !directory.devices.contains(&local_hello.device_certificate)
    {
        return Err(DeviceAdmissionError::Session(
            AslError::InvalidDeviceCertificate,
        ));
    }
    let response = identity_proof_to_wire(request, proof, signed_directory.to_vec());
    let frame = WireFrame::IdentityProof(response);
    encode_frame(&frame).map_err(DeviceAdmissionError::Session)?;
    let WireFrame::IdentityProof(response) = frame else {
        unreachable!()
    };
    Ok(Some(response))
}
