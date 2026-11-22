use std::{path::PathBuf, sync::Arc};

use asl_agent::gateway::{
    HttpModelGateway, ModelGatewayError, ProviderAuthorizationSource, ProviderConfigV1,
    ProviderRegistryV1, validate_provider_id,
};
use asl_policy::snapshot_files::PinnedHome;
use asl_store::{open_store, open_store_read_only};
use asl_types::{error::AslError, task::ProviderId};
use serde::Serialize;

use crate::{paths::AppPaths, providers::DpapiProviderCredentialSource};

#[derive(Serialize)]
pub struct ModelProviderStatus {
    pub config: ProviderConfigV1,
    pub fingerprint: String,
    pub authorized: bool,
}

pub struct ModelEndpointAccess {
    home: PathBuf,
    registry: PathBuf,
    database: PathBuf,
}

impl ModelEndpointAccess {
    pub fn new(paths: &AppPaths) -> Self {
        Self {
            home: paths.dos_root().to_owned(),
            registry: paths.model_provider_configuration(),
            database: paths.state().join("asl.sqlite3"),
        }
    }

    pub fn list(&self) -> Result<Vec<ModelProviderStatus>, AslError> {
        let _pin = PinnedHome::open(&self.home)?;
        let registry = self.registry()?;
        let store = open_store_read_only(&self.database)?;
        registry
            .providers
            .into_iter()
            .map(|config| {
                let fingerprint = fingerprint(&config)?;
                let authorized = config.enabled_by_user
                    && store.model_provider_approval(&config.id.0)?.as_deref()
                        == Some(fingerprint.as_str());
                Ok(ModelProviderStatus {
                    config,
                    fingerprint,
                    authorized,
                })
            })
            .collect()
    }

    pub fn allow(&self, id: &str, reviewed_fingerprint: &str) -> Result<(), AslError> {
        validate_provider_id(id).map_err(|_| AslError::InvalidMessage)?;
        let _pin = PinnedHome::open(&self.home)?;
        let registry = self.registry()?;
        let config = registry
            .providers
            .iter()
            .find(|config| config.id.0 == id)
            .ok_or(AslError::NotFound)?;
        let fingerprint = fingerprint(config)?;
        if !config.enabled_by_user || fingerprint != reviewed_fingerprint {
            return Err(AslError::PolicyDenied);
        }
        open_store(&self.database)?.set_model_provider_approval(id, Some(&fingerprint))
    }

    pub fn revoke(&self, id: &str) -> Result<(), AslError> {
        validate_provider_id(id).map_err(|_| AslError::InvalidMessage)?;
        let _pin = PinnedHome::open(&self.home)?;
        open_store(&self.database)?.set_model_provider_approval(id, None)
    }

    fn registry(&self) -> Result<ProviderRegistryV1, AslError> {
        ProviderRegistryV1::load(&self.registry).map_err(|_| AslError::InvalidPolicyState)
    }

    fn allowed_config(&self, id: &ProviderId) -> Result<ProviderConfigV1, AslError> {
        let _pin = PinnedHome::open(&self.home)?;
        let config = self
            .registry()?
            .providers
            .into_iter()
            .find(|config| &config.id == id && config.enabled_by_user)
            .ok_or(AslError::PolicyDenied)?;
        let fingerprint = fingerprint(&config)?;
        let store = open_store_read_only(&self.database)?;
        if store.model_provider_approval(&id.0)?.as_deref() != Some(fingerprint.as_str()) {
            return Err(AslError::PolicyDenied);
        }
        Ok(config)
    }
}

impl ProviderAuthorizationSource for ModelEndpointAccess {
    fn authorized_config(&self, id: &ProviderId) -> Result<ProviderConfigV1, ModelGatewayError> {
        self.allowed_config(id)
            .map_err(|_| ModelGatewayError::AuthorizationDenied)
    }
}

pub(crate) fn fingerprint(config: &ProviderConfigV1) -> Result<String, AslError> {
    let bytes = serde_json::to_vec(config).map_err(|_| AslError::InvalidPolicyState)?;
    Ok(
        blake3::Hasher::new_derive_key("ASL model provider configuration v1")
            .update(&bytes)
            .finalize()
            .to_hex()
            .to_string(),
    )
}

pub fn configured_model_gateway(paths: &AppPaths) -> Result<HttpModelGateway, ModelGatewayError> {
    HttpModelGateway::new(
        Arc::new(ModelEndpointAccess::new(paths)),
        Arc::new(DpapiProviderCredentialSource::new(
            paths.provider_credentials().to_path_buf(),
        )),
    )
}
