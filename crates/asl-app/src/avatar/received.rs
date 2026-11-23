use asl_store::avatar_publication::MAX_IMAGE_BYTES;
use asl_types::{
    error::AslError,
    ids::Hash32,
    manifest::{Manifest, content_id, encode_manifest},
};

use asl_policy::sandbox::SandboxLauncher;

/// Verify bytes against the expected avatar reference before isolated decoding.
pub(crate) fn sanitize_verified(
    launcher: &SandboxLauncher,
    content: Hash32,
    manifest: &Manifest,
    bytes: &[u8],
) -> Result<Vec<u8>, AslError> {
    verify_payload(content, manifest, bytes)?;
    crate::supervisor::sanitize_avatar_with(launcher, bytes)
}

fn verify_payload(content: Hash32, manifest: &Manifest, bytes: &[u8]) -> Result<(), AslError> {
    if bytes.is_empty() || bytes.len() > MAX_IMAGE_BYTES || manifest.file_size != bytes.len() as u64
    {
        return Err(AslError::InvalidMessage);
    }
    let [chunk_hash] = manifest.chunk_hashes.as_slice() else {
        return Err(AslError::InvalidMessage);
    };
    let canonical = encode_manifest(manifest).map_err(|_| AslError::InvalidMessage)?;
    if content_id(&canonical) != content.0 {
        return Err(AslError::InvalidMessage);
    }

    // The only protocol chunk is the entire file, so one digest checks both fields.
    let digest = blake3::hash(bytes);
    if digest.as_bytes() != &manifest.file_hash || digest.as_bytes() != chunk_hash {
        return Err(AslError::InvalidMessage);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(manifest: &Manifest) -> Hash32 {
        Hash32(content_id(&encode_manifest(manifest).unwrap()))
    }

    #[test]
    fn accepts_matching_payload_at_exact_size_limit() {
        let bytes = vec![7; MAX_IMAGE_BYTES];
        let manifest = Manifest::from_bytes(&bytes).unwrap();
        assert!(verify_payload(id(&manifest), &manifest, &bytes).is_ok());
    }

    #[test]
    fn rejects_empty_and_oversized_payloads_with_valid_manifests() {
        for size in [0, MAX_IMAGE_BYTES + 1] {
            let bytes = vec![7; size];
            let manifest = Manifest::from_bytes(&bytes).unwrap();
            assert!(matches!(
                verify_payload(id(&manifest), &manifest, &bytes),
                Err(AslError::InvalidMessage)
            ));
        }
    }

    #[test]
    fn rejects_wrong_length_and_wrong_chunk_count() {
        let bytes = b"received avatar bytes";
        let manifest = Manifest::from_bytes(bytes).unwrap();
        let mut wrong_length = manifest.clone();
        wrong_length.file_size += 1;
        assert!(verify_payload(id(&wrong_length), &wrong_length, bytes).is_err());

        let content = id(&manifest);
        let mut wrong_count = manifest;
        wrong_count.chunk_hashes.clear();
        assert!(verify_payload(content, &wrong_count, bytes).is_err());
        wrong_count.chunk_hashes = vec![wrong_count.file_hash; 2];
        assert!(verify_payload(content, &wrong_count, bytes).is_err());
    }

    #[test]
    fn rejects_wrong_content_reference_and_either_wrong_digest() {
        let bytes = b"received avatar bytes";
        let manifest = Manifest::from_bytes(bytes).unwrap();
        let content = id(&manifest);
        let mut wrong_content = content;
        wrong_content.0[0] ^= 1;
        assert!(verify_payload(wrong_content, &manifest, bytes).is_err());
        assert!(verify_payload(content, &manifest, b"Received avatar bytes").is_err());

        let mut wrong_file = manifest.clone();
        wrong_file.file_hash[0] ^= 1;
        assert!(verify_payload(id(&wrong_file), &wrong_file, bytes).is_err());
        let mut wrong_chunk = manifest;
        wrong_chunk.chunk_hashes[0][0] ^= 1;
        assert!(verify_payload(id(&wrong_chunk), &wrong_chunk, bytes).is_err());
    }
}
