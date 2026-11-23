const MAGIC: &[u8; 8] = b"ASLMNF01";
const VERSION: u16 = 1;
const HEADER_LEN: usize = 58;
pub const CHUNK_SIZE: u32 = 1_048_576;
const MAX_FILE_SIZE: u64 = 68_719_476_736;
const MAX_CHUNK_COUNT: u32 = 65_536;
const HASH_LEN: usize = 32;
pub const MAX_MANIFEST_LEN: usize = HEADER_LEN + MAX_CHUNK_COUNT as usize * HASH_LEN;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Manifest {
    pub file_size: u64,
    pub file_hash: [u8; 32],
    pub chunk_hashes: Vec<[u8; 32]>,
}

impl Manifest {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ManifestError> {
        let file_size = u64::try_from(bytes.len()).map_err(|_| ManifestError::FileTooLarge)?;
        chunk_count(file_size)?;
        Ok(Self {
            file_size,
            file_hash: *blake3::hash(bytes).as_bytes(),
            chunk_hashes: bytes
                .chunks(CHUNK_SIZE as usize)
                .map(|chunk| *blake3::hash(chunk).as_bytes())
                .collect(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestError {
    TooShort,
    BadMagic,
    BadVersion,
    FileTooLarge,
    BadChunkSize,
    BadChunkCount,
    BadLength,
    BadFileHash,
    ContentIdMismatch,
    IntegerOverflow,
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::TooShort => "manifest is shorter than its fixed header",
            Self::BadMagic => "manifest magic is invalid",
            Self::BadVersion => "manifest version is unsupported",
            Self::FileTooLarge => "manifest file size exceeds the protocol limit",
            Self::BadChunkSize => "manifest chunk size is invalid",
            Self::BadChunkCount => "manifest chunk count does not match file size",
            Self::BadLength => "manifest byte length is invalid",
            Self::BadFileHash => "manifest file hash is invalid for an empty file",
            Self::ContentIdMismatch => "manifest content ID does not match",
            Self::IntegerOverflow => "manifest length calculation overflowed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ManifestError {}

fn chunk_count(file_size: u64) -> Result<u32, ManifestError> {
    if file_size > MAX_FILE_SIZE {
        return Err(ManifestError::FileTooLarge);
    }
    if file_size == 0 {
        return Ok(0);
    }

    let rounded_size = file_size
        .checked_add(u64::from(CHUNK_SIZE) - 1)
        .ok_or(ManifestError::IntegerOverflow)?;
    let count = rounded_size / u64::from(CHUNK_SIZE);
    u32::try_from(count).map_err(|_| ManifestError::BadChunkCount)
}

pub fn content_id(manifest_bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(manifest_bytes).as_bytes()
}

pub fn encoded_len_for_size(file_size: u64) -> Result<usize, ManifestError> {
    Ok(HEADER_LEN + chunk_count(file_size)? as usize * HASH_LEN)
}

pub fn decode_manifest(
    bytes: &[u8],
    expected_content_id: [u8; 32],
) -> Result<Manifest, ManifestError> {
    if bytes.len() < HEADER_LEN {
        return Err(ManifestError::TooShort);
    }
    if bytes.len() > MAX_MANIFEST_LEN {
        return Err(ManifestError::BadLength);
    }
    if &bytes[..8] != MAGIC {
        return Err(ManifestError::BadMagic);
    }

    let version = u16::from_be_bytes([bytes[8], bytes[9]]);
    if version != VERSION {
        return Err(ManifestError::BadVersion);
    }

    let file_size = u64::from_be_bytes(
        bytes[10..18]
            .try_into()
            .map_err(|_| ManifestError::BadLength)?,
    );
    if file_size > MAX_FILE_SIZE {
        return Err(ManifestError::FileTooLarge);
    }
    let chunk_size = u32::from_be_bytes(
        bytes[18..22]
            .try_into()
            .map_err(|_| ManifestError::BadLength)?,
    );
    if chunk_size != CHUNK_SIZE {
        return Err(ManifestError::BadChunkSize);
    }
    let expected_count = chunk_count(file_size)?;

    let declared_count = u32::from_be_bytes(
        bytes[22..26]
            .try_into()
            .map_err(|_| ManifestError::BadLength)?,
    );
    if declared_count != expected_count || declared_count > MAX_CHUNK_COUNT {
        return Err(ManifestError::BadChunkCount);
    }

    let hashes_len = usize::try_from(declared_count)
        .map_err(|_| ManifestError::IntegerOverflow)?
        .checked_mul(HASH_LEN)
        .ok_or(ManifestError::IntegerOverflow)?;
    let expected_len = HEADER_LEN
        .checked_add(hashes_len)
        .ok_or(ManifestError::IntegerOverflow)?;
    if bytes.len() != expected_len {
        return Err(ManifestError::BadLength);
    }

    if content_id(bytes) != expected_content_id {
        return Err(ManifestError::ContentIdMismatch);
    }

    let mut file_hash = [0; 32];
    file_hash.copy_from_slice(&bytes[26..58]);
    if file_size == 0 && file_hash != *blake3::hash(b"").as_bytes() {
        return Err(ManifestError::BadFileHash);
    }
    let chunk_hashes = bytes[HEADER_LEN..]
        .as_chunks::<HASH_LEN>()
        .0
        .iter()
        .map(|hash| {
            let mut chunk_hash = [0; 32];
            chunk_hash.copy_from_slice(hash);
            chunk_hash
        })
        .collect();

    Ok(Manifest {
        file_size,
        file_hash,
        chunk_hashes,
    })
}

pub fn encode_manifest(manifest: &Manifest) -> Result<Vec<u8>, ManifestError> {
    let expected_count = chunk_count(manifest.file_size)?;
    if manifest.chunk_hashes.len() != expected_count as usize || expected_count > MAX_CHUNK_COUNT {
        return Err(ManifestError::BadChunkCount);
    }
    if manifest.file_size == 0 && manifest.file_hash != *blake3::hash(b"").as_bytes() {
        return Err(ManifestError::BadFileHash);
    }
    let hashes_len = manifest
        .chunk_hashes
        .len()
        .checked_mul(HASH_LEN)
        .ok_or(ManifestError::IntegerOverflow)?;
    let capacity = HEADER_LEN
        .checked_add(hashes_len)
        .ok_or(ManifestError::IntegerOverflow)?;
    if capacity > MAX_MANIFEST_LEN {
        return Err(ManifestError::BadLength);
    }

    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&manifest.file_size.to_be_bytes());
    bytes.extend_from_slice(&CHUNK_SIZE.to_be_bytes());
    bytes.extend_from_slice(&expected_count.to_be_bytes());
    bytes.extend_from_slice(&manifest.file_hash);
    for chunk_hash in &manifest.chunk_hashes {
        bytes.extend_from_slice(chunk_hash);
    }
    Ok(bytes)
}
