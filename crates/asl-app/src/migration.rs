use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::Path,
};

use age::{Decryptor, Encryptor, secrecy::SecretString};
use asl_policy::{WriteGrant, snapshot_files::ProfileOwner, validate_storage_root};
use asl_store::{migration::PortableRecords, open_store, open_store_read_only};
use asl_types::{
    error::AslError,
    ids::{AgentId, PeerId},
};
use zeroize::Zeroizing;

use crate::{
    identity::{AgentIdentity, DeviceIdentity},
    paths::{AppPaths, validate_existing_components},
    supervisor::unix_time_ms,
};

pub use asl_store::migration::Selection;

const MAGIC: [u8; 8] = *b"ASLMIG01";
const VERSION: u8 = 1;
const MAX_RECORD_BYTES: usize = 16 << 20;
const MAX_CIPHERTEXT_BYTES: u64 = 17 << 20;
const SCRYPT_WORK_FACTOR: u8 = 18;

pub fn export(
    paths: &AppPaths,
    destination: &Path,
    passphrase: SecretString,
    selection: Selection,
) -> Result<(), AslError> {
    let _owner = ProfileOwner::core(paths.dos_root())?;
    let _downloads = ProfileOwner::downloads(paths.dos_root())?;
    let key_path = paths.agent_root_key();
    validate_existing_components(&key_path)?;
    let identity = AgentIdentity::load_protected(&key_path)?;
    let mut store = open_store_read_only(&paths.existing_state_database()?)?;
    let records = store.portable_records(selection, now()?)?;
    let directory = destination.parent().ok_or(AslError::InvalidStorageRoot)?;
    let filename = Path::new(
        destination
            .file_name()
            .ok_or(AslError::InvalidStorageRoot)?,
    );
    WriteGrant::filename(filename)?;
    let grant = WriteGrant::open(directory, paths.dos_root())?;
    let staging = format!(".asl-migration-{:032x}.tmp", rand::random::<u128>());
    let mut file = grant.create_new(Path::new(&staging))?;
    write_bundle(&mut file, &identity, &records, passphrase)?;
    file.sync_all()?;
    grant.rename_new(&mut file, filename)
}

pub struct MigratedIdentity {
    pub agent_id: AgentId,
    pub peer_id: PeerId,
}

pub fn import_new(
    source: &Path,
    destination: &Path,
    passphrase: SecretString,
) -> Result<MigratedIdentity, AslError> {
    let parent = destination.parent().ok_or(AslError::InvalidStorageRoot)?;
    let filename = Path::new(
        destination
            .file_name()
            .ok_or(AslError::InvalidStorageRoot)?,
    );
    WriteGrant::filename(filename)?;
    require_local_path(parent)?;
    require_absent(destination)?;
    require_local_path(source)?;
    let file = File::open(source)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_CIPHERTEXT_BYTES {
        return Err(AslError::InvalidMessage);
    }
    let (identity, records) = read_bundle(file.take(MAX_CIPHERTEXT_BYTES + 1), passphrase)?;

    let mut staging = tempfile::Builder::new()
        .prefix(".asl-migration-")
        .tempdir_in(parent)?;
    let staging_path = staging.path();
    let paths = AppPaths::open(staging_path)?;
    let mut store = open_store(&paths.state().join("asl.sqlite3"))?;
    store.restore_portable_records(records, now()?)?;
    drop(store);
    identity.save_protected_new(&paths.agent_root_key())?;
    let device = DeviceIdentity::generate()?;
    device.save_protected_new(&paths.device_key())?;
    let result = MigratedIdentity {
        agent_id: identity.agent_id(),
        peer_id: device.peer_id(),
    };
    require_absent(destination)?;
    // Windows refuses to replace an existing destination directory.
    fs::rename(staging_path, destination)?;
    staging.disable_cleanup(true);
    Ok(result)
}

fn write_bundle(
    file: impl Write,
    identity: &AgentIdentity,
    records: &PortableRecords,
    passphrase: SecretString,
) -> Result<(), AslError> {
    let records =
        Zeroizing::new(serde_json::to_vec(records).map_err(|_| AslError::InvalidMessage)?);
    if records.len() > MAX_RECORD_BYTES {
        return Err(AslError::QuotaExceeded);
    }
    let mut recipient = age::scrypt::Recipient::new(passphrase);
    recipient.set_work_factor(SCRYPT_WORK_FACTOR);
    let encryptor = Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
        .map_err(|_| AslError::KeyProtectionFailed)?;
    let mut out = encryptor
        .wrap_output(file)
        .map_err(|_| AslError::KeyProtectionFailed)?;
    out.write_all(&MAGIC)?;
    out.write_all(&[VERSION])?;
    out.write_all(identity.agent_id().as_bytes())?;
    out.write_all(&*identity.migration_seed())?;
    out.write_all(&identity.migration_public_checksum())?;
    out.write_all(&(records.len() as u32).to_be_bytes())?;
    out.write_all(blake3::hash(&records).as_bytes())?;
    out.write_all(&records)?;
    out.finish()?;
    Ok(())
}

fn read_bundle(
    file: impl Read,
    passphrase: SecretString,
) -> Result<(AgentIdentity, PortableRecords), AslError> {
    let decryptor = Decryptor::new(file).map_err(|_| AslError::InvalidMessage)?;
    if !decryptor.is_scrypt() {
        return Err(AslError::InvalidMessage);
    }
    let mut scrypt = age::scrypt::Identity::new(passphrase);
    scrypt.set_max_work_factor(SCRYPT_WORK_FACTOR);
    let mut input = decryptor
        .decrypt(std::iter::once(&scrypt as &dyn age::Identity))
        .map_err(|_| AslError::KeyProtectionFailed)?;
    if read::<8>(&mut input)? != MAGIC || read::<1>(&mut input)? != [VERSION] {
        return Err(AslError::IncompatibleVersion);
    }
    let agent = read::<32>(&mut input)?;
    let mut seed = Zeroizing::new([0; 32]);
    input.read_exact(&mut *seed)?;
    let identity = AgentIdentity::from_migration_seed(&*seed)?;
    if identity.agent_id().0 != agent
        || read::<32>(&mut input)? != identity.migration_public_checksum()
    {
        return Err(AslError::InvalidIdentity);
    }
    let size = u32::from_be_bytes(read::<4>(&mut input)?) as usize;
    if size > MAX_RECORD_BYTES {
        return Err(AslError::QuotaExceeded);
    }
    let digest = read::<32>(&mut input)?;
    let mut records = Zeroizing::new(vec![0; size]);
    input.read_exact(&mut records)?;
    if input.read(&mut [0])? != 0 || blake3::hash(&records).as_bytes() != &digest {
        return Err(AslError::InvalidMessage);
    }
    let records = serde_json::from_slice(&records).map_err(|_| AslError::InvalidMessage)?;
    Ok((identity, records))
}

fn read<const N: usize>(input: &mut impl Read) -> Result<[u8; N], AslError> {
    let mut bytes = [0; N];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn require_local_path(path: &Path) -> Result<(), AslError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(AslError::InvalidStorageRoot);
    }
    validate_storage_root(path)?;
    validate_existing_components(path)
}

fn require_absent(path: &Path) -> Result<(), AslError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(AslError::PolicyDenied),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn now() -> Result<i64, AslError> {
    i64::try_from(unix_time_ms()?).map_err(|_| AslError::InvalidPolicyState)
}
