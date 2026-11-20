use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
};

use asl_agent::gateway::{ModelGatewayError, ProviderCredentialSource, validate_provider_id};
use asl_policy::{protect_secret, unprotect_secret};
use asl_types::task::ProviderId;
use zeroize::Zeroizing;

const MAX_CREDENTIAL_CIPHERTEXT_BYTES: u64 = 8 * 1024;
const MAX_CREDENTIAL_BYTES: usize = 4 * 1024;

pub struct DpapiProviderCredentialSource {
    directory: PathBuf,
}

impl DpapiProviderCredentialSource {
    pub fn new(directory: PathBuf) -> Self {
        Self { directory }
    }

    pub fn store_api_key(
        &self,
        provider: &ProviderId,
        api_key: Zeroizing<Vec<u8>>,
    ) -> Result<(), ModelGatewayError> {
        let path = self.credential_path(provider)?;
        if api_key.is_empty() || api_key.len() > MAX_CREDENTIAL_BYTES {
            return Err(ModelGatewayError::CredentialsUnavailable);
        }
        let ciphertext =
            protect_secret(&api_key).map_err(|_| ModelGatewayError::CredentialsUnavailable)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|_| ModelGatewayError::CredentialsUnavailable)?;
        file.write_all(&ciphertext)
            .and_then(|()| file.sync_all())
            .map_err(|_| ModelGatewayError::CredentialsUnavailable)
    }

    pub fn remove_api_key(&self, provider: &ProviderId) -> Result<(), ModelGatewayError> {
        let path = self.credential_path(provider)?;
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(ModelGatewayError::CredentialsUnavailable),
        }
    }

    fn credential_path(&self, provider: &ProviderId) -> Result<PathBuf, ModelGatewayError> {
        validate_provider_id(&provider.0)?;
        Ok(self
            .directory
            .join(format!("provider-{}.dpapi", provider.0)))
    }
}

impl ProviderCredentialSource for DpapiProviderCredentialSource {
    fn api_key(
        &self,
        provider: &ProviderId,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, ModelGatewayError> {
        let path = self.credential_path(provider)?;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(ModelGatewayError::CredentialsUnavailable),
        };
        if !metadata.file_type().is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_CREDENTIAL_CIPHERTEXT_BYTES
        {
            return Err(ModelGatewayError::CredentialsUnavailable);
        }
        let mut ciphertext = Vec::with_capacity(metadata.len() as usize);
        File::open(path)
            .and_then(|file| {
                file.take(MAX_CREDENTIAL_CIPHERTEXT_BYTES + 1)
                    .read_to_end(&mut ciphertext)
                    .map(|_| ())
            })
            .map_err(|_| ModelGatewayError::CredentialsUnavailable)?;
        if ciphertext.is_empty() || ciphertext.len() as u64 > MAX_CREDENTIAL_CIPHERTEXT_BYTES {
            return Err(ModelGatewayError::CredentialsUnavailable);
        }
        let plaintext =
            unprotect_secret(&ciphertext).map_err(|_| ModelGatewayError::CredentialsUnavailable)?;
        if plaintext.is_empty() || plaintext.len() > MAX_CREDENTIAL_BYTES {
            return Err(ModelGatewayError::CredentialsUnavailable);
        }
        Ok(Some(plaintext))
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn provider_keys_round_trip_through_dpapi_and_are_provider_scoped() {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "asl-provider-credentials-{}-{timestamp}-{}",
            std::process::id(),
            NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&directory).unwrap();

        let source = DpapiProviderCredentialSource::new(directory.clone());
        let provider = ProviderId("provider-a".into());
        source
            .store_api_key(&provider, Zeroizing::new(b"test-only-secret".to_vec()))
            .unwrap();
        assert_eq!(
            source.api_key(&provider).unwrap().unwrap().as_slice(),
            b"test-only-secret"
        );
        assert!(
            source
                .api_key(&ProviderId("provider-b".into()))
                .unwrap()
                .is_none()
        );
        assert!(
            source
                .store_api_key(&provider, Zeroizing::new(b"replacement".to_vec()))
                .is_err()
        );
        source.remove_api_key(&provider).unwrap();
        assert!(source.api_key(&provider).unwrap().is_none());
        assert!(
            source
                .store_api_key(&ProviderId("../outside".into()), Zeroizing::new(vec![1]))
                .is_err()
        );

        fs::remove_dir(directory).unwrap();
    }
}
