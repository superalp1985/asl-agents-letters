use std::{fs::File, io::Read, path::Path};

use asl_types::error::AslError;
use ed25519_dalek::{Signature, VerifyingKey};
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"ASL-WINDOWS-UPDATE-v1\0";
const MAX_MANIFEST_BYTES: usize = 4096;
const MAX_ARCHIVE_BYTES: u64 = 1 << 30;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format_version: u8,
    version: String,
    platform: String,
    archive_bytes: u64,
    sha256: String,
}

#[derive(serde::Serialize)]
pub struct VerifiedPackage {
    pub version: String,
    pub sha256: String,
}

pub fn verify_windows_package(
    public_key: [u8; 32],
    manifest: &[u8],
    signature: [u8; 64],
    archive: impl Read,
    installed: &Version,
) -> Result<Version, AslError> {
    verify_package(public_key, manifest, signature, archive, installed).map(|(version, _)| version)
}

fn verify_package(
    public_key: [u8; 32],
    manifest: &[u8],
    signature: [u8; 64],
    archive: impl Read,
    installed: &Version,
) -> Result<(Version, [u8; 32]), AslError> {
    if manifest.len() > MAX_MANIFEST_BYTES {
        return Err(AslError::InvalidMessage);
    }
    let key = VerifyingKey::from_bytes(&public_key).map_err(|_| AslError::InvalidIdentity)?;
    let message = [DOMAIN, manifest].concat();
    key.verify_strict(&message, &Signature::from_bytes(&signature))
        .map_err(|_| AslError::InvalidIdentity)?;
    let manifest: Manifest =
        serde_json::from_slice(manifest).map_err(|_| AslError::InvalidMessage)?;
    if manifest.format_version != 1 || manifest.platform != "windows-x86_64" {
        return Err(AslError::IncompatibleVersion);
    }
    let version = Version::parse(&manifest.version).map_err(|_| AslError::InvalidMessage)?;
    if !version.cmp_precedence(installed).is_gt() || !version.pre.is_empty() {
        return Err(AslError::PolicyDenied);
    }
    if !(1..=MAX_ARCHIVE_BYTES).contains(&manifest.archive_bytes) {
        return Err(AslError::QuotaExceeded);
    }
    let expected = alloy_primitives::hex::decode_to_array::<_, 32>(&manifest.sha256)
        .map_err(|_| AslError::InvalidMessage)?;
    let mut digest = Sha256::new();
    let mut file = archive.take(manifest.archive_bytes + 1);
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0;
    loop {
        let size = file.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        digest.update(&buffer[..size]);
        total += size as u64;
    }
    if total != manifest.archive_bytes || digest.finalize().as_slice() != expected {
        return Err(AslError::InvalidMessage);
    }
    Ok((version, expected))
}

pub fn verify_local_package(
    key: &Path,
    manifest: &Path,
    signature: &Path,
    package: &Path,
) -> Result<Version, AslError> {
    let verified =
        verify_local_receipt(key, manifest, signature, package, env!("CARGO_PKG_VERSION"))?;
    Version::parse(&verified.version).map_err(|_| AslError::InvalidPolicyState)
}

pub fn verify_local_receipt(
    key: &Path,
    manifest: &Path,
    signature: &Path,
    package: &Path,
    installed: &str,
) -> Result<VerifiedPackage, AslError> {
    let public_key = bounded_file(key, 32)?
        .try_into()
        .map_err(|_| AslError::InvalidIdentity)?;
    let manifest = bounded_file(manifest, MAX_MANIFEST_BYTES)?;
    let signature = bounded_file(signature, 64)?
        .try_into()
        .map_err(|_| AslError::InvalidIdentity)?;
    let installed = Version::parse(installed).map_err(|_| AslError::InvalidPolicyState)?;
    let bootstrap =
        Version::parse(env!("CARGO_PKG_VERSION")).map_err(|_| AslError::InvalidPolicyState)?;
    if installed.cmp_precedence(&bootstrap).is_lt() {
        return Err(AslError::PolicyDenied);
    }
    let (version, hash) = verify_package(
        public_key,
        &manifest,
        signature,
        File::open(package)?,
        &installed,
    )?;
    Ok(VerifiedPackage {
        version: version.to_string(),
        sha256: alloy_primitives::hex::encode(hash),
    })
}

fn bounded_file(path: &Path, limit: usize) -> Result<Vec<u8>, AslError> {
    let mut data = Vec::new();
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut data)?;
    if data.len() > limit {
        return Err(AslError::QuotaExceeded);
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn only_the_signed_new_version_and_exact_package_verify() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let archive = b"portable package fixture";
        let manifest = serde_json::to_vec(&serde_json::json!({
            "format_version": 1,
            "version": "1.2.0",
            "platform": "windows-x86_64",
            "archive_bytes": archive.len(),
            "sha256": alloy_primitives::hex::encode(Sha256::digest(archive)),
        }))
        .unwrap();
        let signature = key.sign(&[DOMAIN, &manifest].concat()).to_bytes();
        let verify = |manifest: &[u8], bytes: &[u8], installed: &str, public: [u8; 32]| {
            verify_windows_package(
                public,
                manifest,
                signature,
                bytes,
                &Version::parse(installed).unwrap(),
            )
        };
        let public = key.verifying_key().to_bytes();
        assert_eq!(
            verify(&manifest, archive, "1.1.0", public)
                .unwrap()
                .to_string(),
            "1.2.0"
        );
        assert!(verify(&manifest, archive, "1.2.0", public).is_err());
        assert!(verify(&manifest, archive, "2.0.0", public).is_err());
        let other = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
        assert!(verify(&manifest, archive, "1.1.0", other).is_err());
        assert!(verify(&manifest, &archive[..archive.len() - 1], "1.1.0", public).is_err());
        assert!(
            verify(
                &manifest,
                &[archive.as_slice(), b"!"].concat(),
                "1.1.0",
                public
            )
            .is_err()
        );
        let mut changed = manifest.clone();
        changed.push(b' ');
        assert!(verify(&changed, archive, "1.1.0", public).is_err());
    }
}
