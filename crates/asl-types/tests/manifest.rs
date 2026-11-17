use asl_types::manifest::{Manifest, ManifestError, content_id, decode_manifest, encode_manifest};

const CHUNK_SIZE: u64 = 1_048_576;
const MAX_FILE_SIZE: u64 = 68_719_476_736;

fn sample(file_size: u64) -> Manifest {
    let count = if file_size == 0 {
        0
    } else {
        (file_size - 1) / CHUNK_SIZE + 1
    };
    Manifest {
        file_size,
        file_hash: if file_size == 0 {
            *blake3::hash(b"").as_bytes()
        } else {
            [0x11; 32]
        },
        chunk_hashes: vec![[0x22; 32]; count as usize],
    }
}

fn encoded_with(file_size: u64, chunk_size: u32, count: u32, hash_count: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(58 + hash_count * 32);
    bytes.extend_from_slice(b"ASLMNF01");
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&file_size.to_be_bytes());
    bytes.extend_from_slice(&chunk_size.to_be_bytes());
    bytes.extend_from_slice(&count.to_be_bytes());
    let file_hash = if file_size == 0 {
        *blake3::hash(b"").as_bytes()
    } else {
        [0x11; 32]
    };
    bytes.extend_from_slice(&file_hash);
    bytes.extend(std::iter::repeat_n(0x22, hash_count * 32));
    bytes
}

#[test]
fn round_trips_empty_and_chunk_boundaries() {
    for file_size in [0, 1, CHUNK_SIZE, CHUNK_SIZE + 1, MAX_FILE_SIZE] {
        let manifest = sample(file_size);
        let bytes = encode_manifest(&manifest).unwrap();
        let decoded = decode_manifest(&bytes, content_id(&bytes)).unwrap();
        assert_eq!(decoded, manifest);
    }

    let empty = encode_manifest(&sample(0)).unwrap();
    assert_eq!(empty.len(), 58);
    assert_eq!(
        decode_manifest(&empty, content_id(&empty))
            .unwrap()
            .chunk_hashes
            .len(),
        0
    );
}

#[test]
fn rejects_short_invalid_and_unsupported_headers() {
    assert_eq!(
        decode_manifest(&[0; 57], [0; 32]),
        Err(ManifestError::TooShort)
    );

    let mut bytes = encoded_with(0, CHUNK_SIZE as u32, 0, 0);
    bytes[0] = b'X';
    assert_eq!(
        decode_manifest(&bytes, content_id(&bytes)),
        Err(ManifestError::BadMagic)
    );

    let mut bytes = encoded_with(0, CHUNK_SIZE as u32, 0, 0);
    bytes[9] = 2;
    assert_eq!(
        decode_manifest(&bytes, content_id(&bytes)),
        Err(ManifestError::BadVersion)
    );

    let bytes = encoded_with(0, 512 * 1024, 0, 0);
    assert_eq!(
        decode_manifest(&bytes, content_id(&bytes)),
        Err(ManifestError::BadChunkSize)
    );
}

#[test]
fn rejects_oversize_files_and_inconsistent_chunk_counts() {
    let bytes = encoded_with(MAX_FILE_SIZE + 1, CHUNK_SIZE as u32, 0, 0);
    assert_eq!(
        decode_manifest(&bytes, content_id(&bytes)),
        Err(ManifestError::FileTooLarge)
    );

    let bytes = encoded_with(1, CHUNK_SIZE as u32, 0, 0);
    assert_eq!(
        decode_manifest(&bytes, content_id(&bytes)),
        Err(ManifestError::BadChunkCount)
    );

    let bytes = encoded_with(1, CHUNK_SIZE as u32, u32::MAX, 0);
    assert_eq!(
        decode_manifest(&bytes, content_id(&bytes)),
        Err(ManifestError::BadChunkCount)
    );

    assert_eq!(
        encode_manifest(&sample(MAX_FILE_SIZE + 1)),
        Err(ManifestError::FileTooLarge)
    );
}

#[test]
fn validates_empty_file_hash() {
    let mut manifest = sample(0);
    manifest.file_hash = [0x11; 32];
    assert_eq!(encode_manifest(&manifest), Err(ManifestError::BadFileHash));

    let mut bytes = encoded_with(0, CHUNK_SIZE as u32, 0, 0);
    bytes[26] ^= 1;
    assert_eq!(
        decode_manifest(&bytes, content_id(&bytes)),
        Err(ManifestError::BadFileHash)
    );
}

#[test]
fn rejects_truncation_trailing_bytes_and_content_id_mismatch() {
    let valid = encode_manifest(&sample(CHUNK_SIZE + 1)).unwrap();
    let expected_id = content_id(&valid);

    assert_eq!(
        decode_manifest(
            &valid[..valid.len() - 1],
            content_id(&valid[..valid.len() - 1])
        ),
        Err(ManifestError::BadLength)
    );

    let mut trailing = valid.clone();
    trailing.push(0);
    assert_eq!(
        decode_manifest(&trailing, content_id(&trailing)),
        Err(ManifestError::BadLength)
    );

    assert_eq!(
        decode_manifest(&valid, [0; 32]),
        Err(ManifestError::ContentIdMismatch)
    );

    let mut modified = valid;
    modified[26] ^= 1;
    assert_eq!(
        decode_manifest(&modified, expected_id),
        Err(ManifestError::ContentIdMismatch)
    );
}

#[test]
fn rejects_encoder_hash_count_mismatch() {
    let mut manifest = sample(1);
    manifest.chunk_hashes.clear();
    assert_eq!(
        encode_manifest(&manifest),
        Err(ManifestError::BadChunkCount)
    );
}

#[test]
fn accepts_exact_maximum_manifest_length() {
    let manifest = sample(MAX_FILE_SIZE);
    let bytes = encode_manifest(&manifest).unwrap();
    assert_eq!(bytes.len(), 2_097_210);
    assert_eq!(
        decode_manifest(&bytes, content_id(&bytes)).unwrap(),
        manifest
    );
}
