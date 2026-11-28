use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::Path,
    str::FromStr,
};

use age::{Decryptor, Encryptor, secrecy::SecretString};
use alloy_primitives::hex;
use asl_policy::{WriteGrant, snapshot_files::ProfileOwner, validate_storage_root};
use asl_store::{migration::PortableRecords, open_store, open_store_read_only};
use asl_types::{
    error::AslError,
    ids::{AgentId, PeerId, Signature65},
    record::{RecordPayload, decode_record, record_signing_bytes},
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    identity::{AgentIdentity, DeviceIdentity, verify_device_certificate, verify_root_signature},
    paths::{AppPaths, validate_existing_components},
    supervisor::unix_time_ms,
};

pub use asl_store::migration::Selection;

const MAGIC: [u8; 8] = *b"ASLMIG01";
const VERSION: u8 = 2;
const MAX_RECORD_BYTES: usize = 16 << 20;
const MAX_PAYLOAD_BYTES: usize = MAX_RECORD_BYTES + 32 * 1024;
const MAX_CIPHERTEXT_BYTES: u64 = 17 << 20;
const SCRYPT_WORK_FACTOR: u8 = 18;
const MAX_MIGRATION_STATUS_BYTES: u64 = 64 * 1024;
const MIGRATION_STATUS_FILENAME: &str = "identity-migration-status-v1.json";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceDeviceV1 {
    pub peer_id: String,
    pub certificate_serial: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityMigrationPhaseV1 {
    AwaitingOldDeviceRevocationAuthorization,
    ReadyForOnboarding,
    DirectoryRegistered,
    ReadyToJoin,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityMigrationStatusV1 {
    pub version: u16,
    pub agent_id: String,
    pub source_device: Option<SourceDeviceV1>,
    pub source_directory: Option<String>,
    #[serde(default)]
    pub source_directory_verified: bool,
    pub old_device_revocation_authorized: bool,
    pub old_device_revocation_signature: Option<String>,
    pub next_device_serial: u64,
    pub previous_revoked_serials: Vec<u64>,
    pub new_device_peer_id: String,
    pub phase: IdentityMigrationPhaseV1,
    pub updated_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MigrationOriginV1 {
    source_device: Option<SourceDeviceV1>,
    source_directory: Option<String>,
    source_directory_verified: bool,
    next_device_serial: u64,
    previous_revoked_serials: Vec<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MigrationPayloadV2 {
    records: PortableRecords,
    origin: MigrationOriginV1,
}

#[derive(Serialize)]
struct MigrationPayloadV2Ref<'a> {
    records: &'a PortableRecords,
    origin: &'a MigrationOriginV1,
}

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
    let origin = migration_origin(paths, &identity)?;
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
    write_bundle(&mut file, &identity, &records, &origin, passphrase)?;
    file.sync_all()?;
    grant.rename_new(&mut file, filename)
}

pub struct MigratedIdentity {
    pub agent_id: AgentId,
    pub peer_id: PeerId,
    pub migration: IdentityMigrationStatusV1,
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
    let (identity, records, origin) = read_bundle(file.take(MAX_CIPHERTEXT_BYTES + 1), passphrase)?;

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
    let phase = if origin.source_device.is_some() {
        IdentityMigrationPhaseV1::AwaitingOldDeviceRevocationAuthorization
    } else {
        IdentityMigrationPhaseV1::ReadyForOnboarding
    };
    let status = IdentityMigrationStatusV1 {
        version: 1,
        agent_id: bs58::encode(identity.agent_id().as_bytes()).into_string(),
        source_device: origin.source_device,
        source_directory: origin.source_directory,
        source_directory_verified: origin.source_directory_verified,
        old_device_revocation_authorized: false,
        old_device_revocation_signature: None,
        next_device_serial: origin.next_device_serial,
        previous_revoked_serials: origin.previous_revoked_serials,
        new_device_peer_id: peer_id_text(&device.peer_id()),
        phase,
        updated_at_ms: unix_time_ms()?,
    };
    persist_status(&paths, &status)?;
    let result = MigratedIdentity {
        agent_id: identity.agent_id(),
        peer_id: device.peer_id(),
        migration: status,
    };
    require_absent(destination)?;
    // Windows refuses to replace an existing destination directory.
    fs::rename(staging_path, destination)?;
    staging.disable_cleanup(true);
    Ok(result)
}

pub fn status(paths: &AppPaths) -> Result<Option<IdentityMigrationStatusV1>, AslError> {
    let identity = AgentIdentity::load_protected(&paths.agent_root_key())?;
    load_status(paths, &identity)
}

pub fn authorize_old_device_revocation(
    paths: &AppPaths,
    expected_peer_id: &str,
) -> Result<IdentityMigrationStatusV1, AslError> {
    let identity = AgentIdentity::load_protected(&paths.agent_root_key())?;
    let mut status = load_status(paths, &identity)?.ok_or(AslError::NotFound)?;
    let source = status
        .source_device
        .as_ref()
        .ok_or(AslError::PolicyDenied)?;
    if expected_peer_id != source.peer_id
        || status.phase != IdentityMigrationPhaseV1::AwaitingOldDeviceRevocationAuthorization
    {
        return Err(AslError::PolicyDenied);
    }
    let message = revocation_authorization_message(&identity, source, &status.new_device_peer_id)?;
    status.old_device_revocation_signature =
        Some(hex::encode(identity.sign_domain_message(&message)?.0));
    status.old_device_revocation_authorized = true;
    status.phase = IdentityMigrationPhaseV1::ReadyForOnboarding;
    status.updated_at_ms = unix_time_ms()?;
    persist_status(paths, &status)?;
    Ok(status)
}

pub fn mark_directory_registered(paths: &AppPaths) -> Result<(), AslError> {
    update_phase(paths, IdentityMigrationPhaseV1::DirectoryRegistered, true)
}

pub fn mark_ready_to_join(paths: &AppPaths) -> Result<(), AslError> {
    update_phase(paths, IdentityMigrationPhaseV1::ReadyToJoin, true)
}

fn update_phase(
    paths: &AppPaths,
    phase: IdentityMigrationPhaseV1,
    allow_unverified_legacy_origin: bool,
) -> Result<(), AslError> {
    let identity = AgentIdentity::load_protected(&paths.agent_root_key())?;
    let Some(mut status) = load_status(paths, &identity)? else {
        return Ok(());
    };
    if status.source_device.is_some() && !status.old_device_revocation_authorized {
        return Err(AslError::PolicyDenied);
    }
    let legacy_without_source = status.source_device.is_none()
        && status.source_directory.is_none()
        && !status.source_directory_verified
        && status.next_device_serial == 1
        && status.previous_revoked_serials.is_empty();
    if !status.source_directory_verified
        && !(allow_unverified_legacy_origin && legacy_without_source)
    {
        return Err(AslError::PolicyDenied);
    }
    status.phase = phase;
    status.updated_at_ms = unix_time_ms()?;
    persist_status(paths, &status)
}

fn write_bundle(
    file: impl Write,
    identity: &AgentIdentity,
    records: &PortableRecords,
    origin: &MigrationOriginV1,
    passphrase: SecretString,
) -> Result<(), AslError> {
    let records = Zeroizing::new(
        serde_json::to_vec(&MigrationPayloadV2Ref { records, origin })
            .map_err(|_| AslError::InvalidMessage)?,
    );
    if records.len() > MAX_PAYLOAD_BYTES {
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
) -> Result<(AgentIdentity, PortableRecords, MigrationOriginV1), AslError> {
    let decryptor = Decryptor::new(file).map_err(|_| AslError::InvalidMessage)?;
    if !decryptor.is_scrypt() {
        return Err(AslError::InvalidMessage);
    }
    let mut scrypt = age::scrypt::Identity::new(passphrase);
    scrypt.set_max_work_factor(SCRYPT_WORK_FACTOR);
    let mut input = decryptor
        .decrypt(std::iter::once(&scrypt as &dyn age::Identity))
        .map_err(|_| AslError::KeyProtectionFailed)?;
    if read::<8>(&mut input)? != MAGIC {
        return Err(AslError::IncompatibleVersion);
    }
    let version = read::<1>(&mut input)?[0];
    if !matches!(version, 1 | VERSION) {
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
    let max_size = if version == 1 {
        MAX_RECORD_BYTES
    } else {
        MAX_PAYLOAD_BYTES
    };
    if size > max_size {
        return Err(AslError::QuotaExceeded);
    }
    let digest = read::<32>(&mut input)?;
    let mut records = Zeroizing::new(vec![0; size]);
    input.read_exact(&mut records)?;
    if input.read(&mut [0])? != 0 || blake3::hash(&records).as_bytes() != &digest {
        return Err(AslError::InvalidMessage);
    }
    let (records, origin) = if version == 1 {
        let records = serde_json::from_slice(&records).map_err(|_| AslError::InvalidMessage)?;
        (
            records,
            MigrationOriginV1 {
                source_device: None,
                source_directory: None,
                source_directory_verified: false,
                next_device_serial: 1,
                previous_revoked_serials: Vec::new(),
            },
        )
    } else {
        let payload: MigrationPayloadV2 =
            serde_json::from_slice(&records).map_err(|_| AslError::InvalidMessage)?;
        validate_origin(&payload.origin, &identity)?;
        (payload.records, payload.origin)
    };
    Ok((identity, records, origin))
}

fn migration_origin(
    paths: &AppPaths,
    identity: &AgentIdentity,
) -> Result<MigrationOriginV1, AslError> {
    let directory_path = paths.signed_device_directory();
    let metadata = match fs::symlink_metadata(&directory_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(MigrationOriginV1 {
                source_device: None,
                source_directory: None,
                source_directory_verified: false,
                next_device_serial: 1,
                previous_revoked_serials: Vec::new(),
            });
        }
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file()
        || metadata.len() > asl_types::record::MAX_RECORD_BYTES as u64
    {
        return Err(AslError::InvalidIdentity);
    }
    validate_existing_components(&directory_path)?;
    let directory_bytes = fs::read(directory_path)?;
    let record = decode_record(&directory_bytes)?;
    verify_root_signature(
        &record_signing_bytes(&record.record)?,
        record.signature,
        identity.controller_address(),
    )?;
    let RecordPayload::DeviceDirectory(directory) = record.record.payload else {
        return Err(AslError::InvalidIdentity);
    };
    if directory.agent_id != identity.agent_id() {
        return Err(AslError::InvalidIdentity);
    }
    let device = DeviceIdentity::load_protected(&paths.device_key())?;
    let certificate = directory
        .devices
        .iter()
        .find(|certificate| certificate.peer_id == device.peer_id())
        .ok_or(AslError::InvalidIdentity)?;
    if directory
        .revoked_serials
        .binary_search(&certificate.serial)
        .is_ok()
    {
        return Err(AslError::InvalidIdentity);
    }
    let now_ms = unix_time_ms()?;
    if now_ms < certificate.issued_at_ms {
        return Err(AslError::InvalidIdentity);
    }
    let source_device = if now_ms < certificate.expires_at_ms {
        verify_device_certificate(
            certificate,
            identity.agent_id(),
            &device.peer_id(),
            identity.controller_address(),
            1,
            now_ms,
        )?;
        Some(SourceDeviceV1 {
            peer_id: peer_id_text(&device.peer_id()),
            certificate_serial: certificate.serial,
        })
    } else {
        None
    };
    let highest_serial = directory
        .devices
        .iter()
        .map(|certificate| certificate.serial)
        .chain(directory.revoked_serials.iter().copied())
        .max()
        .unwrap_or(0);
    let origin = MigrationOriginV1 {
        source_device,
        source_directory: Some(hex::encode(directory_bytes)),
        source_directory_verified: true,
        next_device_serial: highest_serial
            .checked_add(1)
            .ok_or(AslError::InvalidIdentity)?,
        previous_revoked_serials: directory.revoked_serials,
    };
    validate_origin(&origin, identity)?;
    Ok(origin)
}

fn validate_origin(origin: &MigrationOriginV1, identity: &AgentIdentity) -> Result<(), AslError> {
    if origin.next_device_serial == 0 || origin.previous_revoked_serials.len() > 64 {
        return Err(AslError::InvalidMessage);
    }
    if origin
        .previous_revoked_serials
        .iter()
        .any(|serial| *serial == 0 || *serial >= origin.next_device_serial)
        || origin
            .previous_revoked_serials
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(AslError::InvalidMessage);
    }
    if let Some(source) = &origin.source_device {
        let peer = parse_peer_id(&source.peer_id)?;
        if source.peer_id != peer_id_text(&peer)
            || source.certificate_serial == 0
            || source.certificate_serial >= origin.next_device_serial
            || origin
                .previous_revoked_serials
                .binary_search(&source.certificate_serial)
                .is_ok()
        {
            return Err(AslError::InvalidMessage);
        }
    }
    match (&origin.source_directory, origin.source_directory_verified) {
        (Some(encoded), true) => {
            let bytes = hex::decode(encoded).map_err(|_| AslError::InvalidMessage)?;
            if bytes.len() > asl_types::record::MAX_RECORD_BYTES {
                return Err(AslError::QuotaExceeded);
            }
            let record = decode_record(&bytes)?;
            let RecordPayload::DeviceDirectory(directory) = &record.record.payload else {
                return Err(AslError::InvalidIdentity);
            };
            if directory.agent_id != identity.agent_id()
                || directory.revoked_serials != origin.previous_revoked_serials
            {
                return Err(AslError::InvalidIdentity);
            }
            verify_root_signature(
                &record_signing_bytes(&record.record)?,
                record.signature,
                identity.controller_address(),
            )?;
            let highest_serial = directory
                .devices
                .iter()
                .map(|certificate| certificate.serial)
                .chain(directory.revoked_serials.iter().copied())
                .max()
                .unwrap_or(0);
            if highest_serial.checked_add(1) != Some(origin.next_device_serial) {
                return Err(AslError::InvalidIdentity);
            }
            if let Some(source) = &origin.source_device
                && !directory.devices.iter().any(|certificate| {
                    peer_id_text(&certificate.peer_id) == source.peer_id
                        && certificate.serial == source.certificate_serial
                })
            {
                return Err(AslError::InvalidIdentity);
            }
        }
        (Some(_), false) => return Err(AslError::InvalidIdentity),
        (None, true) => return Err(AslError::InvalidIdentity),
        (None, false)
            if origin.source_device.is_some()
                || origin.next_device_serial != 1
                || !origin.previous_revoked_serials.is_empty() =>
        {
            return Err(AslError::InvalidIdentity);
        }
        (None, false) => {}
    }
    Ok(())
}

fn load_status(
    paths: &AppPaths,
    identity: &AgentIdentity,
) -> Result<Option<IdentityMigrationStatusV1>, AslError> {
    let path = paths.state().join(MIGRATION_STATUS_FILENAME);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file() || metadata.len() > MAX_MIGRATION_STATUS_BYTES {
        return Err(AslError::InvalidIdentity);
    }
    validate_existing_components(&path)?;
    let status: IdentityMigrationStatusV1 =
        serde_json::from_slice(&fs::read(path)?).map_err(|_| AslError::InvalidIdentity)?;
    let awaiting =
        status.phase == IdentityMigrationPhaseV1::AwaitingOldDeviceRevocationAuthorization;
    validate_origin(
        &MigrationOriginV1 {
            source_device: status.source_device.clone(),
            source_directory: status.source_directory.clone(),
            source_directory_verified: status.source_directory_verified,
            next_device_serial: status.next_device_serial,
            previous_revoked_serials: status.previous_revoked_serials.clone(),
        },
        identity,
    )?;
    if status.source_device.is_some() && !status.source_directory_verified {
        return Err(AslError::InvalidIdentity);
    }
    let local_agent_id = bs58::encode(identity.agent_id().as_bytes()).into_string();
    let local_peer_id =
        peer_id_text(&DeviceIdentity::load_protected(&paths.device_key())?.peer_id());
    let signature_valid = match (
        status.source_device.as_ref(),
        status.old_device_revocation_authorized,
        status.old_device_revocation_signature.as_deref(),
    ) {
        (Some(source), true, Some(signature)) => {
            let message =
                revocation_authorization_message(identity, source, &status.new_device_peer_id)?;
            let mut signature_bytes = [0; Signature65::LENGTH];
            hex::decode_to_slice(signature, &mut signature_bytes).is_ok()
                && crate::identity::verify_root_signature(
                    &message,
                    Signature65(signature_bytes),
                    identity.controller_address(),
                )
                .is_ok()
        }
        (Some(_), false, None) | (None, false, None) => true,
        _ => false,
    };
    if status.version != 1
        || status.agent_id != local_agent_id
        || status.new_device_peer_id != local_peer_id
        || status.next_device_serial == 0
        || status.previous_revoked_serials.len() > 64
        || status
            .previous_revoked_serials
            .iter()
            .any(|serial| *serial == 0 || *serial >= status.next_device_serial)
        || status
            .previous_revoked_serials
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || !is_canonical_peer_id(&status.new_device_peer_id)
        || !signature_valid
        || status
            .source_device
            .as_ref()
            .is_some_and(|_| status.old_device_revocation_authorized == awaiting)
        || (status.source_device.is_none() && (status.old_device_revocation_authorized || awaiting))
    {
        return Err(AslError::InvalidIdentity);
    }
    Ok(Some(status))
}

fn persist_status(paths: &AppPaths, status: &IdentityMigrationStatusV1) -> Result<(), AslError> {
    let path = paths.state().join(MIGRATION_STATUS_FILENAME);
    let bytes = serde_json::to_vec(status).map_err(|_| AslError::InvalidMessage)?;
    if bytes.len() as u64 > MAX_MIGRATION_STATUS_BYTES {
        return Err(AslError::QuotaExceeded);
    }
    validate_existing_components(&path)?;
    let staging = path.with_extension(format!("{:032x}.tmp", rand::random::<u128>()));
    {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&staging)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    if path.exists() {
        fs::remove_file(&path)?;
    }
    fs::rename(staging, path)?;
    Ok(())
}

fn parse_peer_id(value: &str) -> Result<PeerId, AslError> {
    let peer = libp2p_identity::PeerId::from_str(value).map_err(|_| AslError::InvalidIdentity)?;
    PeerId::from_bytes(peer.to_bytes()).map_err(|_| AslError::InvalidIdentity)
}

fn is_canonical_peer_id(value: &str) -> bool {
    parse_peer_id(value).is_ok_and(|peer| value == peer_id_text(&peer))
}

fn revocation_authorization_message(
    identity: &AgentIdentity,
    source: &SourceDeviceV1,
    new_device_peer_id: &str,
) -> Result<Vec<u8>, AslError> {
    const DOMAIN: &[u8] = b"ASL-MIGRATION-REVOKE-OLD-DEVICE-v1\0";
    let old_peer = parse_peer_id(&source.peer_id)?;
    let new_peer = parse_peer_id(new_device_peer_id)?;
    if source.certificate_serial == 0
        || source.peer_id != peer_id_text(&old_peer)
        || new_device_peer_id != peer_id_text(&new_peer)
    {
        return Err(AslError::InvalidIdentity);
    }
    let old_bytes = old_peer.as_bytes();
    let new_bytes = new_peer.as_bytes();
    let old_length = u16::try_from(old_bytes.len()).map_err(|_| AslError::InvalidIdentity)?;
    let new_length = u16::try_from(new_bytes.len()).map_err(|_| AslError::InvalidIdentity)?;
    let mut message = Vec::with_capacity(
        DOMAIN.len() + AgentId::LENGTH + 8 + 2 + old_bytes.len() + 2 + new_bytes.len(),
    );
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(identity.agent_id().as_bytes());
    message.extend_from_slice(&source.certificate_serial.to_be_bytes());
    message.extend_from_slice(&old_length.to_be_bytes());
    message.extend_from_slice(old_bytes);
    message.extend_from_slice(&new_length.to_be_bytes());
    message.extend_from_slice(new_bytes);
    Ok(message)
}

fn peer_id_text(peer: &PeerId) -> String {
    libp2p_identity::PeerId::from_bytes(peer.as_bytes())
        .map(|peer| peer.to_string())
        .unwrap_or_default()
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
