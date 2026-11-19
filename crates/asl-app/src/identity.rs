use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

use asl_policy::{protect_secret, unprotect_secret};
use asl_types::{
    error::AslError,
    ids::{AgentId, PeerId, Signature65},
    protocol::DeviceCertificate,
};
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use libp2p_identity::KeyType;
use rand::{TryRng, rngs::SysRng};
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

const AGENT_DOMAIN: &[u8] = b"ASL-Agent-v1";
const DEVICE_DOMAIN: &[u8] = b"ASL-DEVICE-v1\0";
const ROOT_FILE_MAGIC: &[u8] = b"ASL-ROOT-v1\0";
const DEVICE_FILE_MAGIC: &[u8] = b"ASL-DEVICE-KEY-v1\0";
const ROOT_ADDRESS_LENGTH: usize = 20;
const PRIVATE_KEY_LENGTH: usize = 32;
pub(crate) const MAX_DEVICE_KEY_BYTES: usize = 1024;
const MAX_DEVICE_CERTIFICATE_LIFETIME_MS: u64 = 30 * 24 * 60 * 60 * 1_000;

pub struct AgentIdentity {
    agent_id: AgentId,
    initial_root_address: [u8; ROOT_ADDRESS_LENGTH],
    signing_key: SigningKey,
}

impl AgentIdentity {
    pub fn generate() -> Result<Self, AslError> {
        let signing_key = generate_root_key()?;
        let initial_root_address = root_address(signing_key.verifying_key());
        let agent_id = derive_agent_id(initial_root_address);
        Ok(Self {
            agent_id,
            initial_root_address,
            signing_key,
        })
    }

    pub fn agent_id(&self) -> AgentId {
        self.agent_id
    }

    pub fn controller_address(&self) -> [u8; ROOT_ADDRESS_LENGTH] {
        root_address(self.signing_key.verifying_key())
    }

    pub fn save_protected_new(&self, path: &Path) -> Result<(), AslError> {
        let plaintext = self.protected_payload();
        write_protected_new(path, &plaintext)
    }

    pub fn load_protected(path: &Path) -> Result<Self, AslError> {
        let ciphertext = fs::read(path)?;
        let plaintext = unprotect_secret(&ciphertext)?;
        if plaintext.len() != ROOT_FILE_MAGIC.len() + 32 + ROOT_ADDRESS_LENGTH + PRIVATE_KEY_LENGTH
            || !plaintext.starts_with(ROOT_FILE_MAGIC)
        {
            return Err(AslError::InvalidIdentity);
        }

        let agent_start = ROOT_FILE_MAGIC.len();
        let address_start = agent_start + 32;
        let key_start = address_start + ROOT_ADDRESS_LENGTH;
        let agent_id = AgentId(
            plaintext[agent_start..address_start]
                .try_into()
                .map_err(|_| AslError::InvalidIdentity)?,
        );
        let initial_root_address = plaintext[address_start..key_start]
            .try_into()
            .map_err(|_| AslError::InvalidIdentity)?;
        let signing_key = SigningKey::from_slice(&plaintext[key_start..])
            .map_err(|_| AslError::InvalidIdentity)?;

        if derive_agent_id(initial_root_address) != agent_id
            || root_address(signing_key.verifying_key()) != initial_root_address
        {
            return Err(AslError::InvalidIdentity);
        }

        Ok(Self {
            agent_id,
            initial_root_address,
            signing_key,
        })
    }

    pub fn issue_device_certificate(
        &self,
        peer_id: PeerId,
        serial: u64,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> Result<DeviceCertificate, AslError> {
        validate_certificate_fields(serial, issued_at_ms, expires_at_ms)?;
        let message = device_certificate_message(
            self.agent_id,
            &peer_id,
            serial,
            issued_at_ms,
            expires_at_ms,
        )?;
        Ok(DeviceCertificate {
            agent_id: self.agent_id,
            peer_id,
            serial,
            issued_at_ms,
            expires_at_ms,
            signature: self.sign_domain_message(&message)?,
        })
    }

    pub(crate) fn sign_domain_message(&self, message: &[u8]) -> Result<Signature65, AslError> {
        let digest = Keccak256::digest(message);
        let (signature, recovery_id) = self.signing_key.sign_prehash_recoverable(&digest);
        if recovery_id.to_byte() > 1 {
            return Err(AslError::InvalidIdentity);
        }
        let mut bytes = [0; Signature65::LENGTH];
        bytes[..64].copy_from_slice(&signature.to_bytes());
        bytes[64] = recovery_id.to_byte() + 27;
        Ok(Signature65(bytes))
    }

    fn protected_payload(&self) -> Zeroizing<Vec<u8>> {
        let mut plaintext = Zeroizing::new(Vec::with_capacity(
            ROOT_FILE_MAGIC.len() + 32 + ROOT_ADDRESS_LENGTH + PRIVATE_KEY_LENGTH,
        ));
        plaintext.extend_from_slice(ROOT_FILE_MAGIC);
        plaintext.extend_from_slice(self.agent_id.as_bytes());
        plaintext.extend_from_slice(&self.initial_root_address);
        let private_key = Zeroizing::new(self.signing_key.to_bytes());
        plaintext.extend_from_slice(private_key.as_ref());
        plaintext
    }
}

pub struct DeviceIdentity {
    keypair: libp2p_identity::Keypair,
    peer_id: PeerId,
}

impl DeviceIdentity {
    pub fn generate() -> Result<Self, AslError> {
        let mut secret = Zeroizing::new([0; 32]);
        SysRng
            .try_fill_bytes(&mut *secret)
            .map_err(|_| AslError::InvalidIdentity)?;
        let secret_key = libp2p_identity::ed25519::SecretKey::try_from_bytes(&mut *secret)
            .map_err(|_| AslError::InvalidIdentity)?;
        let ed25519_keypair = libp2p_identity::ed25519::Keypair::from(secret_key);
        Self::from_keypair(libp2p_identity::Keypair::from(ed25519_keypair))
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id.clone()
    }

    pub fn save_protected_new(&self, path: &Path) -> Result<(), AslError> {
        let encoded = Zeroizing::new(
            self.keypair
                .to_protobuf_encoding()
                .map_err(|_| AslError::InvalidIdentity)?,
        );
        let mut plaintext =
            Zeroizing::new(Vec::with_capacity(DEVICE_FILE_MAGIC.len() + encoded.len()));
        plaintext.extend_from_slice(DEVICE_FILE_MAGIC);
        plaintext.extend_from_slice(&encoded);
        write_protected_new(path, &plaintext)
    }

    pub fn load_or_create_protected(path: &Path) -> Result<Self, AslError> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_file() => Self::load_protected(path),
            Ok(_) => Err(AslError::InvalidIdentity),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let identity = Self::generate()?;
                match identity.save_protected_new(path) {
                    Ok(()) => Ok(identity),
                    Err(AslError::Io(error))
                        if error.kind() == std::io::ErrorKind::AlreadyExists =>
                    {
                        Self::load_protected(path)
                    }
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn load_protected(path: &Path) -> Result<Self, AslError> {
        let ciphertext = fs::read(path)?;
        let plaintext = Zeroizing::new(unprotect_secret(&ciphertext)?);
        let Some(encoded) = plaintext.strip_prefix(DEVICE_FILE_MAGIC) else {
            return Err(AslError::InvalidIdentity);
        };
        Self::from_ipc_secret(encoded)
    }

    pub(crate) fn to_ipc_secret(&self) -> Result<Zeroizing<Vec<u8>>, AslError> {
        let encoded = Zeroizing::new(
            self.keypair
                .to_protobuf_encoding()
                .map_err(|_| AslError::InvalidIdentity)?,
        );
        if encoded.is_empty() || encoded.len() > MAX_DEVICE_KEY_BYTES {
            return Err(AslError::InvalidIdentity);
        }
        Ok(encoded)
    }

    pub(crate) fn from_ipc_secret(encoded: &[u8]) -> Result<Self, AslError> {
        if encoded.is_empty() || encoded.len() > MAX_DEVICE_KEY_BYTES {
            return Err(AslError::InvalidIdentity);
        }
        let keypair = libp2p_identity::Keypair::from_protobuf_encoding(encoded)
            .map_err(|_| AslError::InvalidIdentity)?;

        if keypair.public().key_type() != KeyType::Ed25519 {
            return Err(AslError::InvalidIdentity);
        }

        Self::from_keypair(keypair)
    }

    fn from_keypair(keypair: libp2p_identity::Keypair) -> Result<Self, AslError> {
        let peer_id = PeerId::from_bytes(keypair.public().to_peer_id().to_bytes())
            .map_err(|_| AslError::InvalidIdentity)?;
        Ok(Self { keypair, peer_id })
    }
}

pub fn verify_device_certificate(
    certificate: &DeviceCertificate,
    expected_agent_id: AgentId,
    expected_peer_id: &PeerId,
    expected_controller_address: [u8; ROOT_ADDRESS_LENGTH],
    minimum_serial: u64,
    now_ms: u64,
) -> Result<(), AslError> {
    validate_certificate_fields(
        certificate.serial,
        certificate.issued_at_ms,
        certificate.expires_at_ms,
    )?;

    if certificate.agent_id != expected_agent_id
        || &certificate.peer_id != expected_peer_id
        || certificate.serial < minimum_serial
    {
        return Err(AslError::InvalidDeviceCertificate);
    }
    if now_ms < certificate.issued_at_ms || now_ms >= certificate.expires_at_ms {
        return Err(AslError::ExpiredMessage);
    }

    let message = device_certificate_message(
        certificate.agent_id,
        &certificate.peer_id,
        certificate.serial,
        certificate.issued_at_ms,
        certificate.expires_at_ms,
    )?;
    verify_root_signature(&message, certificate.signature, expected_controller_address)
        .map_err(|_| AslError::InvalidDeviceCertificate)
}

pub(crate) fn verify_root_signature(
    message: &[u8],
    signature_bytes: Signature65,
    expected_controller_address: [u8; ROOT_ADDRESS_LENGTH],
) -> Result<(), AslError> {
    let digest = Keccak256::digest(message);
    let signature =
        Signature::from_slice(&signature_bytes.0[..64]).map_err(|_| AslError::InvalidIdentity)?;
    if signature.normalize_s() != signature {
        return Err(AslError::InvalidIdentity);
    }
    let recovery_id = signature_bytes.0[64]
        .checked_sub(27)
        .and_then(RecoveryId::from_byte)
        .filter(|recovery_id| recovery_id.to_byte() <= 1)
        .ok_or(AslError::InvalidIdentity)?;
    let recovered = VerifyingKey::recover_from_prehash(&digest, &signature, recovery_id)
        .map_err(|_| AslError::InvalidIdentity)?;

    if root_address(&recovered) != expected_controller_address {
        return Err(AslError::InvalidIdentity);
    }
    Ok(())
}

fn generate_root_key() -> Result<SigningKey, AslError> {
    let mut secret = Zeroizing::new([0; PRIVATE_KEY_LENGTH]);
    SysRng
        .try_fill_bytes(&mut *secret)
        .map_err(|_| AslError::InvalidIdentity)?;
    SigningKey::from_slice(&*secret).map_err(|_| AslError::InvalidIdentity)
}

fn derive_agent_id(initial_root_address: [u8; ROOT_ADDRESS_LENGTH]) -> AgentId {
    let mut preimage = Vec::with_capacity(AGENT_DOMAIN.len() + ROOT_ADDRESS_LENGTH);
    preimage.extend_from_slice(AGENT_DOMAIN);
    preimage.extend_from_slice(&initial_root_address);
    AgentId(Keccak256::digest(preimage).into())
}

fn root_address(verifying_key: &VerifyingKey) -> [u8; ROOT_ADDRESS_LENGTH] {
    let public_key = verifying_key.to_sec1_point(false);
    let digest = Keccak256::digest(&public_key.as_bytes()[1..]);
    let mut address = [0; ROOT_ADDRESS_LENGTH];
    address.copy_from_slice(&digest[12..]);
    address
}

fn validate_certificate_fields(
    serial: u64,
    issued_at_ms: u64,
    expires_at_ms: u64,
) -> Result<(), AslError> {
    if serial == 0
        || expires_at_ms <= issued_at_ms
        || expires_at_ms - issued_at_ms > MAX_DEVICE_CERTIFICATE_LIFETIME_MS
    {
        return Err(AslError::InvalidDeviceCertificate);
    }
    Ok(())
}

fn device_certificate_message(
    agent_id: AgentId,
    peer_id: &PeerId,
    serial: u64,
    issued_at_ms: u64,
    expires_at_ms: u64,
) -> Result<Vec<u8>, AslError> {
    let peer_bytes = peer_id.as_bytes();
    let peer_length =
        u16::try_from(peer_bytes.len()).map_err(|_| AslError::InvalidDeviceCertificate)?;
    let mut message = Vec::with_capacity(DEVICE_DOMAIN.len() + 32 + 2 + peer_bytes.len() + 24);
    message.extend_from_slice(DEVICE_DOMAIN);
    message.extend_from_slice(agent_id.as_bytes());
    message.extend_from_slice(&peer_length.to_be_bytes());
    message.extend_from_slice(peer_bytes);
    message.extend_from_slice(&serial.to_be_bytes());
    message.extend_from_slice(&issued_at_ms.to_be_bytes());
    message.extend_from_slice(&expires_at_ms.to_be_bytes());
    Ok(message)
}

fn write_protected_new(path: &Path, plaintext: &[u8]) -> Result<(), AslError> {
    let ciphertext = protect_secret(plaintext)?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    if let Err(error) = file.write_all(&ciphertext).and_then(|()| file.sync_all()) {
        return Err(error.into());
    }
    Ok(())
}

#[cfg(all(test, windows))]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::{AgentIdentity, generate_root_key};
    use asl_policy::protect_secret;
    use zeroize::Zeroizing;

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn rejects_root_key_that_does_not_match_saved_agent_id() {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../work/test-identity");
        fs::create_dir_all(&base).unwrap();
        let path = base.join(format!(
            "mismatched-root-{}-{}.dpapi",
            std::process::id(),
            NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));

        let identity = AgentIdentity::generate().unwrap();
        let mut plaintext = identity.protected_payload();
        let key_start = plaintext.len() - 32;
        let replacement_key = Zeroizing::new(generate_root_key().unwrap().to_bytes());
        plaintext[key_start..].copy_from_slice(&replacement_key[..]);
        fs::write(&path, protect_secret(&plaintext).unwrap()).unwrap();

        assert!(AgentIdentity::load_protected(&path).is_err());
        fs::remove_file(path).unwrap();
    }
}
