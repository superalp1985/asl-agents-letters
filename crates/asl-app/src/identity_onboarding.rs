use std::{
    fs,
    io::Write,
    net::IpAddr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use alloy_primitives::hex;
use asl_store::open_store;
use asl_types::{
    error::AslError,
    record::{
        DeviceDirectory, MAX_RECORD_LIFETIME_MS, RecordPayload, decode_record,
        device_directory_commitment,
    },
};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    chain::{
        ChainHttpClient, DurableIdentityResolver, IdentityResolution, IdentityResolver,
        RegistryDeploymentV1, RegistryStatus,
    },
    checkpoint_access,
    identity::{AgentIdentity, DeviceIdentity, verify_device_certificate},
    identity_registration::{
        IdentityRegistrationRequest, default_deadline, prepare_device_directory,
    },
    migration::{self, IdentityMigrationStatusV1},
    network_identity::NetworkIdentityConfigurationV1,
    network_settings::{NetworkSettingsV1, SignedNetworkSeedsStatusV1},
    paths::{AppPaths, validate_local_absolute_path},
    profile::sign_record,
};

const CONFIG_MAX_BYTES: u64 = 64 * 1024;
const STATUS_MAX_BYTES: u64 = 512 * 1024;
const SPONSOR_RESPONSE_MAX_BYTES: usize = 16 * 1024;
const SIGNER_RESPONSE_MAX_BYTES: usize = 256 * 1024;
const RAW_TRANSACTION_MAX_BYTES: usize = 128 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionModeV1 {
    Sponsor,
    SelfPay,
    Fallback,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SponsorEndpointV1 {
    pub url: String,
    pub allow_loopback_http: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfPaySignerV1 {
    pub executable: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmissionConfigV1 {
    pub mode: SubmissionModeV1,
    pub sponsors: Vec<SponsorEndpointV1>,
    pub self_pay: Option<SelfPaySignerV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityOnboardingConfigV1 {
    pub version: u16,
    pub submission: SubmissionConfigV1,
    pub finality_timeout_seconds: u64,
    pub finality_poll_seconds: u64,
    pub publication_timeout_seconds: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnboardingPhaseV1 {
    Prepared,
    Submitted,
    DirectoryInstalled,
    ReadyToJoin,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionRouteV1 {
    Sponsor,
    SelfPay,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnboardingDraftV1 {
    pub operation: String,
    pub registry_sequence: u64,
    pub state_commitment: String,
    pub signed_directory: String,
    pub request: Value,
    pub deadline: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityOnboardingStatusV1 {
    pub version: u16,
    pub agent_id: String,
    pub chain_id: u64,
    pub registry: String,
    pub phase: OnboardingPhaseV1,
    pub operation: Option<String>,
    pub registry_sequence: u64,
    pub state_commitment: String,
    pub draft: Option<OnboardingDraftV1>,
    pub transaction_hash: Option<String>,
    pub submission_route: Option<SubmissionRouteV1>,
    pub directory_published: bool,
    pub last_error: Option<String>,
    pub updated_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SetupConfigurationStateV1 {
    Missing,
    Defaulted,
    Configured,
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SetupNetworkSeedsStateV1 {
    NotConfigured,
    ExplicitBootstrapConfigured,
    SignedSeedsRequired,
    SignedSeedsVerified,
    Invalid,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SetupNetworkSeedsStatusV1 {
    pub state: SetupNetworkSeedsStateV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified: Option<SignedNetworkSeedsStatusV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SetupStageV1 {
    ConfigurationRequired,
    MigrationAuthorizationRequired,
    ReadyToOnboard,
    RegistrationPrepared,
    WaitingForFinality,
    DirectoryPublicationPending,
    ReadyToJoin,
    Revoked,
    Blocked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SetupNextActionV1 {
    ProvideNetworkIdentityConfiguration,
    ProvideIdentityOnboardingConfiguration,
    ImportSignedNetworkSeeds,
    InstallSelfPaySigner,
    AuthorizeOldDeviceRevocation,
    RunIdentityOnboarding,
    ResumeIdentityOnboarding,
    StartAgent,
    RepairNetworkSettings,
    RepairSignedNetworkSeeds,
    RepairNetworkIdentityConfiguration,
    RepairIdentityOnboardingConfiguration,
    RepairIdentityOnboardingStatus,
    RepairIdentityMigrationStatus,
    ReplaceOrRestoreActiveIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExternalPrerequisiteStateV1 {
    Required,
    ConfiguredNotChecked,
    ConfirmedByFinalizedChainProof,
    ConfirmedByLocalAcknowledgement,
    NotRequired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExternalPrerequisiteV1 {
    pub name: String,
    pub state: ExternalPrerequisiteStateV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuidedOnboardingProgressV1 {
    pub phase: OnboardingPhaseV1,
    pub operation: Option<String>,
    pub registry_sequence: u64,
    pub transaction_submitted: bool,
    pub directory_published: bool,
    pub last_error: Option<String>,
    pub updated_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuidedMigrationProgressV1 {
    pub phase: migration::IdentityMigrationPhaseV1,
    pub old_device_authorization_required: bool,
    pub source_directory_verified: bool,
    pub updated_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuidedSetupStatusV1 {
    pub schema: String,
    pub stage: SetupStageV1,
    pub next_action: SetupNextActionV1,
    pub ready_to_start: bool,
    pub can_resume_onboarding: bool,
    pub network_settings: SetupConfigurationStateV1,
    pub network_seeds: SetupNetworkSeedsStatusV1,
    pub network_identity: SetupConfigurationStateV1,
    pub identity_onboarding: SetupConfigurationStateV1,
    pub onboarding: Option<GuidedOnboardingProgressV1>,
    pub migration: Option<GuidedMigrationProgressV1>,
    pub external_prerequisites: Vec<ExternalPrerequisiteV1>,
}

impl IdentityOnboardingConfigV1 {
    pub fn load(path: &Path) -> Result<Self, AslError> {
        let bytes = read_bounded(path, CONFIG_MAX_BYTES)?;
        let config: Self = serde_json::from_slice(&bytes).map_err(|_| AslError::InvalidIdentity)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), AslError> {
        if self.version != 1
            || self.finality_timeout_seconds == 0
            || self.finality_poll_seconds == 0
            || self.publication_timeout_seconds == 0
            || self.submission.sponsors.len() > 16
        {
            return Err(AslError::InvalidIdentity);
        }
        for sponsor in &self.submission.sponsors {
            validated_url(&sponsor.url, sponsor.allow_loopback_http)?;
        }
        match self.submission.mode {
            SubmissionModeV1::Sponsor if self.submission.sponsors.is_empty() => {
                return Err(AslError::InvalidIdentity);
            }
            SubmissionModeV1::SelfPay if self.submission.self_pay.is_none() => {
                return Err(AslError::InvalidIdentity);
            }
            SubmissionModeV1::Fallback
                if self.submission.sponsors.is_empty() && self.submission.self_pay.is_none() =>
            {
                return Err(AslError::InvalidIdentity);
            }
            _ => {}
        }
        if let Some(signer) = &self.submission.self_pay {
            validate_local_absolute_path(&signer.executable)?;
        }
        Ok(())
    }
}

pub fn status(paths: &AppPaths) -> Result<Option<IdentityOnboardingStatusV1>, AslError> {
    let identity = AgentIdentity::load_protected(&paths.agent_root_key())?;
    let network = NetworkIdentityConfigurationV1::load(&paths.network_identity_configuration())?
        .ok_or(AslError::InvalidIdentity)?;
    load_status(
        &paths.identity_onboarding_status(),
        *identity.agent_id().as_bytes(),
        network.resolver.deployment,
    )
}

pub(crate) fn guided_setup_status(paths: &AppPaths) -> Result<GuidedSetupStatusV1, AslError> {
    AgentIdentity::load_protected(&paths.agent_root_key())?;
    DeviceIdentity::load_protected(&paths.device_key())?;

    let network_settings_path = paths.network_settings_configuration();
    let network_settings_present = network_settings_path.try_exists()?;
    let (network_settings_state, network_settings) =
        match NetworkSettingsV1::load(&network_settings_path) {
            Ok(settings) => (
                if network_settings_present {
                    SetupConfigurationStateV1::Configured
                } else {
                    SetupConfigurationStateV1::Defaulted
                },
                Some(settings),
            ),
            Err(_) => (SetupConfigurationStateV1::Invalid, None),
        };

    let seeds_path = paths.network_seeds();
    let seeds_present = seeds_path.try_exists()?;
    let network_seeds = match network_settings.as_ref() {
        None => SetupNetworkSeedsStatusV1 {
            state: SetupNetworkSeedsStateV1::Invalid,
            verified: None,
        },
        Some(settings) if !settings.bootstrap_multiaddrs.is_empty() => SetupNetworkSeedsStatusV1 {
            state: if seeds_present {
                SetupNetworkSeedsStateV1::Invalid
            } else {
                SetupNetworkSeedsStateV1::ExplicitBootstrapConfigured
            },
            verified: None,
        },
        Some(settings) if seeds_present => {
            match settings.signed_seed_file_status(&seeds_path, unix_time_ms()?) {
                Ok(Some(verified)) => SetupNetworkSeedsStatusV1 {
                    state: SetupNetworkSeedsStateV1::SignedSeedsVerified,
                    verified: Some(verified),
                },
                _ => SetupNetworkSeedsStatusV1 {
                    state: SetupNetworkSeedsStateV1::Invalid,
                    verified: None,
                },
            }
        }
        Some(settings) if settings.network_seed_public_key.is_some() => SetupNetworkSeedsStatusV1 {
            state: SetupNetworkSeedsStateV1::SignedSeedsRequired,
            verified: None,
        },
        Some(_) => SetupNetworkSeedsStatusV1 {
            state: SetupNetworkSeedsStateV1::NotConfigured,
            verified: None,
        },
    };

    let (network_identity_state, network_identity) =
        match NetworkIdentityConfigurationV1::load(&paths.network_identity_configuration()) {
            Ok(Some(configuration)) => (SetupConfigurationStateV1::Configured, Some(configuration)),
            Ok(None) => (SetupConfigurationStateV1::Missing, None),
            Err(_) => (SetupConfigurationStateV1::Invalid, None),
        };

    let onboarding_path = paths.identity_onboarding_configuration();
    let (onboarding_configuration_state, onboarding_configuration) =
        if onboarding_path.try_exists()? {
            match IdentityOnboardingConfigV1::load(&onboarding_path) {
                Ok(configuration) => (SetupConfigurationStateV1::Configured, Some(configuration)),
                Err(_) => (SetupConfigurationStateV1::Invalid, None),
            }
        } else {
            (SetupConfigurationStateV1::Missing, None)
        };

    let (migration, migration_invalid) = match migration::status(paths) {
        Ok(status) => (status, false),
        Err(_) => (None, true),
    };
    let (onboarding, onboarding_status_invalid) = if network_identity.is_some() {
        match status(paths) {
            Ok(status) => (status, false),
            Err(_) => (None, true),
        }
    } else {
        (None, false)
    };
    let self_pay_signer_missing = onboarding_configuration
        .as_ref()
        .is_some_and(|configuration| {
            configuration.submission.mode == SubmissionModeV1::SelfPay
                && !self_pay_signer_ready(configuration)
        });

    let seed_state = network_seeds.state;
    let (stage, next_action) = if network_settings_state == SetupConfigurationStateV1::Invalid {
        (
            SetupStageV1::Blocked,
            SetupNextActionV1::RepairNetworkSettings,
        )
    } else if seed_state == SetupNetworkSeedsStateV1::Invalid {
        (
            SetupStageV1::Blocked,
            SetupNextActionV1::RepairSignedNetworkSeeds,
        )
    } else if network_identity_state == SetupConfigurationStateV1::Invalid {
        (
            SetupStageV1::Blocked,
            SetupNextActionV1::RepairNetworkIdentityConfiguration,
        )
    } else if onboarding_configuration_state == SetupConfigurationStateV1::Invalid {
        (
            SetupStageV1::Blocked,
            SetupNextActionV1::RepairIdentityOnboardingConfiguration,
        )
    } else if migration_invalid {
        (
            SetupStageV1::Blocked,
            SetupNextActionV1::RepairIdentityMigrationStatus,
        )
    } else if onboarding_status_invalid {
        (
            SetupStageV1::Blocked,
            SetupNextActionV1::RepairIdentityOnboardingStatus,
        )
    } else if network_identity_state == SetupConfigurationStateV1::Missing {
        (
            SetupStageV1::ConfigurationRequired,
            SetupNextActionV1::ProvideNetworkIdentityConfiguration,
        )
    } else if onboarding_configuration_state == SetupConfigurationStateV1::Missing {
        (
            SetupStageV1::ConfigurationRequired,
            SetupNextActionV1::ProvideIdentityOnboardingConfiguration,
        )
    } else if self_pay_signer_missing {
        (
            SetupStageV1::ConfigurationRequired,
            SetupNextActionV1::InstallSelfPaySigner,
        )
    } else if migration.as_ref().is_some_and(|status| {
        status.phase
            == migration::IdentityMigrationPhaseV1::AwaitingOldDeviceRevocationAuthorization
    }) {
        (
            SetupStageV1::MigrationAuthorizationRequired,
            SetupNextActionV1::AuthorizeOldDeviceRevocation,
        )
    } else if seed_state == SetupNetworkSeedsStateV1::SignedSeedsRequired {
        (
            SetupStageV1::ConfigurationRequired,
            SetupNextActionV1::ImportSignedNetworkSeeds,
        )
    } else {
        match onboarding.as_ref().map(|status| status.phase) {
            None => (
                SetupStageV1::ReadyToOnboard,
                SetupNextActionV1::RunIdentityOnboarding,
            ),
            Some(OnboardingPhaseV1::Prepared) => (
                SetupStageV1::RegistrationPrepared,
                SetupNextActionV1::ResumeIdentityOnboarding,
            ),
            Some(OnboardingPhaseV1::Submitted) => (
                SetupStageV1::WaitingForFinality,
                SetupNextActionV1::ResumeIdentityOnboarding,
            ),
            Some(OnboardingPhaseV1::DirectoryInstalled) => (
                SetupStageV1::DirectoryPublicationPending,
                SetupNextActionV1::ResumeIdentityOnboarding,
            ),
            Some(OnboardingPhaseV1::ReadyToJoin) => {
                (SetupStageV1::ReadyToJoin, SetupNextActionV1::StartAgent)
            }
            Some(OnboardingPhaseV1::Revoked) => (
                SetupStageV1::Revoked,
                SetupNextActionV1::ReplaceOrRestoreActiveIdentity,
            ),
        }
    };

    let finalized_registry_proof = onboarding.as_ref().is_some_and(|status| {
        matches!(
            status.phase,
            OnboardingPhaseV1::DirectoryInstalled
                | OnboardingPhaseV1::ReadyToJoin
                | OnboardingPhaseV1::Revoked
        )
    });
    let mut external_prerequisites = vec![ExternalPrerequisiteV1 {
        name: "identity_registry_deployment".into(),
        state: if network_identity.is_none() {
            ExternalPrerequisiteStateV1::Required
        } else if finalized_registry_proof {
            ExternalPrerequisiteStateV1::ConfirmedByFinalizedChainProof
        } else {
            ExternalPrerequisiteStateV1::ConfiguredNotChecked
        },
    }];
    external_prerequisites.push(ExternalPrerequisiteV1 {
        name: "chain_rpc_availability".into(),
        state: if network_identity.is_some() {
            ExternalPrerequisiteStateV1::ConfiguredNotChecked
        } else {
            ExternalPrerequisiteStateV1::Required
        },
    });
    append_submission_prerequisites(
        &mut external_prerequisites,
        onboarding_configuration.as_ref(),
    );
    external_prerequisites.push(ExternalPrerequisiteV1 {
        name: "peer_discovery".into(),
        state: match seed_state {
            SetupNetworkSeedsStateV1::SignedSeedsVerified
            | SetupNetworkSeedsStateV1::ExplicitBootstrapConfigured => {
                ExternalPrerequisiteStateV1::ConfiguredNotChecked
            }
            SetupNetworkSeedsStateV1::NotConfigured
                if network_settings
                    .as_ref()
                    .is_some_and(|settings| !settings.relay_addresses.is_empty()) =>
            {
                ExternalPrerequisiteStateV1::ConfiguredNotChecked
            }
            SetupNetworkSeedsStateV1::NotConfigured
                if network_settings.as_ref().is_some_and(|settings| {
                    settings.address_scope
                        == crate::network_settings::NetworkAddressScopeV1::LoopbackOnly
                }) =>
            {
                ExternalPrerequisiteStateV1::NotRequired
            }
            _ => ExternalPrerequisiteStateV1::Required,
        },
    });
    external_prerequisites.push(ExternalPrerequisiteV1 {
        name: "device_directory_publication".into(),
        state: if onboarding
            .as_ref()
            .is_some_and(|status| status.directory_published)
        {
            ExternalPrerequisiteStateV1::ConfirmedByLocalAcknowledgement
        } else if finalized_registry_proof || network_identity.is_none() {
            ExternalPrerequisiteStateV1::Required
        } else {
            ExternalPrerequisiteStateV1::ConfiguredNotChecked
        },
    });
    let onboarding_progress = onboarding
        .as_ref()
        .map(|status| GuidedOnboardingProgressV1 {
            phase: status.phase,
            operation: status.operation.clone(),
            registry_sequence: status.registry_sequence,
            transaction_submitted: status.transaction_hash.is_some(),
            directory_published: status.directory_published,
            last_error: status.last_error.clone(),
            updated_at_ms: status.updated_at_ms,
        });
    let migration_progress = migration.as_ref().map(|status| GuidedMigrationProgressV1 {
        phase: status.phase.clone(),
        old_device_authorization_required: status.phase
            == migration::IdentityMigrationPhaseV1::AwaitingOldDeviceRevocationAuthorization,
        source_directory_verified: status.source_directory_verified,
        updated_at_ms: status.updated_at_ms,
    });

    Ok(GuidedSetupStatusV1 {
        schema: "asl-guided-setup-status-v1".into(),
        stage,
        next_action,
        ready_to_start: stage == SetupStageV1::ReadyToJoin,
        can_resume_onboarding: matches!(
            next_action,
            SetupNextActionV1::RunIdentityOnboarding | SetupNextActionV1::ResumeIdentityOnboarding
        ),
        network_settings: network_settings_state,
        network_seeds,
        network_identity: network_identity_state,
        identity_onboarding: onboarding_configuration_state,
        onboarding: onboarding_progress,
        migration: migration_progress,
        external_prerequisites,
    })
}

fn append_submission_prerequisites(
    prerequisites: &mut Vec<ExternalPrerequisiteV1>,
    configuration: Option<&IdentityOnboardingConfigV1>,
) {
    let Some(configuration) = configuration else {
        prerequisites.push(ExternalPrerequisiteV1 {
            name: "identity_submission_route".into(),
            state: ExternalPrerequisiteStateV1::Required,
        });
        return;
    };
    if matches!(
        configuration.submission.mode,
        SubmissionModeV1::Sponsor | SubmissionModeV1::Fallback
    ) {
        prerequisites.push(ExternalPrerequisiteV1 {
            name: "sponsor_service_availability".into(),
            state: ExternalPrerequisiteStateV1::ConfiguredNotChecked,
        });
    }
    if matches!(
        configuration.submission.mode,
        SubmissionModeV1::SelfPay | SubmissionModeV1::Fallback
    ) {
        prerequisites.push(ExternalPrerequisiteV1 {
            name: "self_pay_signer_and_funding".into(),
            state: if self_pay_signer_ready(configuration) {
                ExternalPrerequisiteStateV1::ConfiguredNotChecked
            } else {
                ExternalPrerequisiteStateV1::Required
            },
        });
    }
}

fn self_pay_signer_ready(configuration: &IdentityOnboardingConfigV1) -> bool {
    configuration
        .submission
        .self_pay
        .as_ref()
        .is_some_and(|signer| {
            validate_local_absolute_path(&signer.executable).is_ok()
                && fs::symlink_metadata(&signer.executable)
                    .is_ok_and(|metadata| metadata.file_type().is_file())
        })
}

/// Runs the durable chain-registration state machine and installs the signed
/// device directory after an independently finalized registry proof matches the
/// registered commitment. DHT publication is a separate typed step.
pub fn onboard(paths: &AppPaths) -> Result<IdentityOnboardingStatusV1, AslError> {
    let config = IdentityOnboardingConfigV1::load(&paths.identity_onboarding_configuration())?;
    config.validate()?;
    let identity = AgentIdentity::load_protected(&paths.agent_root_key())?;
    let device = DeviceIdentity::load_protected(&paths.device_key())?;
    let migration_status = migration::status(paths)?;
    validate_migration_onboarding(&migration_status, &identity, &device)?;
    let network = NetworkIdentityConfigurationV1::load(&paths.network_identity_configuration())?
        .ok_or(AslError::InvalidIdentity)?;
    let deployment = network.resolver.deployment;
    let database = paths.existing_state_database()?;
    let (network, http, runtime, mut resolver) = open_chain(network, &database)?;

    let initial_ms = unix_time_ms()?;
    let mut state = load_status(
        &paths.identity_onboarding_status(),
        *identity.agent_id().as_bytes(),
        deployment,
    )?
    .unwrap_or_else(|| new_status(&identity, deployment, initial_ms));

    if matches!(
        state.phase,
        OnboardingPhaseV1::ReadyToJoin | OnboardingPhaseV1::Revoked
    ) {
        return Ok(state);
    }

    let now_secs = unix_time_secs()?;
    let now_ms = unix_time_ms()?;
    let resolution = refresh_resolution(
        &runtime,
        &http,
        &mut resolver,
        identity.agent_id(),
        now_secs,
    )?;
    match resolution {
        IdentityResolution::Limited(crate::chain::LimitedReason::Revoked) => {
            state.phase = OnboardingPhaseV1::Revoked;
            state.last_error = None;
            persist_status(paths, &mut state, now_ms)?;
            return Ok(state);
        }
        IdentityResolution::Limited(crate::chain::LimitedReason::Unregistered) => {
            prepare_register(paths, &mut state, &identity, &device, deployment, now_ms)?;
        }
        IdentityResolution::Verified(verified) => {
            if verified.state().status != RegistryStatus::Active
                || verified.state().controller != identity.controller_address()
            {
                return Err(AslError::InvalidIdentity);
            }
            if migration_status.as_ref().is_some_and(|migration| {
                !migration.source_directory_verified && !is_unverified_legacy_migration(migration)
            }) {
                return Err(AslError::PolicyDenied);
            }
            if state.draft.as_ref().is_some_and(|draft| {
                draft.registry_sequence == verified.state().sequence
                    && draft.state_commitment == hex32(verified.state().state_commitment)
            }) {
                let draft = state.draft.as_ref().expect("draft checked");
                install_directory(
                    &paths.signed_device_directory(),
                    &decode_hex(&draft.signed_directory)?,
                )?;
                state.phase = OnboardingPhaseV1::DirectoryInstalled;
                state.last_error = None;
                persist_status(paths, &mut state, now_ms)?;
                migration::mark_directory_registered(paths)?;
                return Ok(state);
            }
            let next = verified
                .state()
                .sequence
                .checked_add(1)
                .ok_or(AslError::InvalidMessage)?;
            prepare_update(
                paths, &mut state, &identity, &device, deployment, next, now_ms,
            )?;
        }
        IdentityResolution::Limited(_) => return Err(AslError::InvalidIdentity),
    }

    if state.transaction_hash.is_none() {
        let (hash, route) = submit_registration(
            &config.submission,
            &network.http,
            state.draft.as_ref().ok_or(AslError::InvalidPolicyState)?,
        )?;
        state.transaction_hash = Some(hash);
        state.submission_route = Some(route);
        state.phase = OnboardingPhaseV1::Submitted;
        state.last_error = None;
        persist_status(paths, &mut state, unix_time_ms()?)?;
    }

    wait_for_finality(
        paths,
        &config,
        &runtime,
        &http,
        &mut resolver,
        &mut state,
        identity.agent_id(),
    )?;
    let draft = state.draft.as_ref().ok_or(AslError::InvalidPolicyState)?;
    let bytes = decode_hex(&draft.signed_directory)?;
    install_directory(&paths.signed_device_directory(), &bytes)?;
    state.phase = OnboardingPhaseV1::DirectoryInstalled;
    state.directory_published = false;
    state.last_error = None;
    persist_status(paths, &mut state, unix_time_ms()?)?;
    migration::mark_directory_registered(paths)?;
    Ok(state)
}

/// Submits a signed revocation through the same configured sponsor/self-pay
/// policy and waits for a finalized revoked proof. A durable local hook is
/// emitted before returning so the running Core can suspend admission.
pub fn revoke(
    paths: &AppPaths,
    sequence: u64,
    deadline: u64,
) -> Result<IdentityOnboardingStatusV1, AslError> {
    if sequence <= 1 || deadline == 0 {
        return Err(AslError::InvalidMessage);
    }
    let config = IdentityOnboardingConfigV1::load(&paths.identity_onboarding_configuration())?;
    config.validate()?;
    let identity = AgentIdentity::load_protected(&paths.agent_root_key())?;
    let network = NetworkIdentityConfigurationV1::load(&paths.network_identity_configuration())?
        .ok_or(AslError::InvalidIdentity)?;
    let deployment = network.resolver.deployment;
    let database = paths.existing_state_database()?;
    let (network, http, runtime, mut resolver) = open_chain(network, &database)?;
    let now = unix_time_secs()?;
    let resolution = refresh_resolution(&runtime, &http, &mut resolver, identity.agent_id(), now)?;
    if !matches!(
        resolution,
        IdentityResolution::Verified(ref verified)
            if verified.state().status == RegistryStatus::Active
                && verified.state().sequence.checked_add(1) == Some(sequence)
                && verified.state().controller == identity.controller_address()
    ) {
        return Err(AslError::PolicyVersionConflict);
    }
    let request =
        IdentityRegistrationRequest::build_revoke(&identity, deployment, sequence, deadline)?;
    let initial_ms = unix_time_ms()?;
    let mut state = load_status(
        &paths.identity_onboarding_status(),
        *identity.agent_id().as_bytes(),
        deployment,
    )?
    .unwrap_or_else(|| new_status(&identity, deployment, initial_ms));
    state.phase = OnboardingPhaseV1::Prepared;
    state.operation = Some("revoke".into());
    state.registry_sequence = sequence;
    state.state_commitment.clear();
    state.transaction_hash = None;
    state.submission_route = None;
    state.directory_published = false;
    state.last_error = None;
    state.draft = Some(draft(
        "revoke",
        sequence,
        [0; 32],
        &[],
        serde_json::to_value(&request).map_err(|_| AslError::InvalidMessage)?,
        deadline,
    ));
    persist_status(paths, &mut state, unix_time_ms()?)?;

    let (hash, route) = submit_registration(
        &config.submission,
        &network.http,
        state.draft.as_ref().ok_or(AslError::InvalidPolicyState)?,
    )?;
    state.transaction_hash = Some(hash);
    state.submission_route = Some(route);
    state.phase = OnboardingPhaseV1::Submitted;
    persist_status(paths, &mut state, unix_time_ms()?)?;
    let wait_deadline = Instant::now() + Duration::from_secs(config.finality_timeout_seconds);
    loop {
        let resolution = refresh_resolution(
            &runtime,
            &http,
            &mut resolver,
            identity.agent_id(),
            unix_time_secs()?,
        )?;
        if matches!(
            resolution,
            IdentityResolution::Limited(crate::chain::LimitedReason::Revoked)
        ) {
            state.phase = OnboardingPhaseV1::Revoked;
            state.last_error = None;
            persist_status(paths, &mut state, unix_time_ms()?)?;
            emit_revocation_hook(paths, &state)?;
            return Ok(state);
        }
        if Instant::now() >= wait_deadline {
            state.last_error = Some("revocation finality wait timed out".into());
            persist_status(paths, &mut state, unix_time_ms()?)?;
            return Err(AslError::ExpiredMessage);
        }
        std::thread::sleep(Duration::from_secs(config.finality_poll_seconds));
    }
}

pub fn mark_directory_published(
    paths: &AppPaths,
    expected_commitment: &str,
) -> Result<IdentityOnboardingStatusV1, AslError> {
    let identity = AgentIdentity::load_protected(&paths.agent_root_key())?;
    let network = NetworkIdentityConfigurationV1::load(&paths.network_identity_configuration())?
        .ok_or(AslError::InvalidIdentity)?;
    let mut status = load_status(
        &paths.identity_onboarding_status(),
        *identity.agent_id().as_bytes(),
        network.resolver.deployment,
    )?
    .ok_or(AslError::NotFound)?;
    if status.state_commitment != expected_commitment
        || !matches!(
            status.phase,
            OnboardingPhaseV1::DirectoryInstalled | OnboardingPhaseV1::ReadyToJoin
        )
    {
        return Err(AslError::InvalidIdentity);
    }
    status.phase = OnboardingPhaseV1::ReadyToJoin;
    status.directory_published = true;
    status.last_error = None;
    persist_status(paths, &mut status, unix_time_ms()?)?;
    migration::mark_ready_to_join(paths)?;
    Ok(status)
}

pub fn note_publication_failure(
    paths: &AppPaths,
    expected_commitment: &str,
    message: &str,
) -> Result<IdentityOnboardingStatusV1, AslError> {
    let identity = AgentIdentity::load_protected(&paths.agent_root_key())?;
    let network = NetworkIdentityConfigurationV1::load(&paths.network_identity_configuration())?
        .ok_or(AslError::InvalidIdentity)?;
    let mut status = load_status(
        &paths.identity_onboarding_status(),
        *identity.agent_id().as_bytes(),
        network.resolver.deployment,
    )?
    .ok_or(AslError::NotFound)?;
    if status.state_commitment != expected_commitment
        || status.phase != OnboardingPhaseV1::DirectoryInstalled
    {
        return Err(AslError::InvalidIdentity);
    }
    status.last_error = Some(message.chars().take(512).collect());
    persist_status(paths, &mut status, unix_time_ms()?)?;
    Ok(status)
}

fn validate_migration_onboarding(
    status: &Option<IdentityMigrationStatusV1>,
    identity: &AgentIdentity,
    device: &DeviceIdentity,
) -> Result<(), AslError> {
    let Some(status) = status else {
        return Ok(());
    };
    let peer = libp2p_identity::PeerId::from_bytes(device.peer_id().as_bytes())
        .map_err(|_| AslError::InvalidIdentity)?;
    if status.agent_id != bs58::encode(identity.agent_id().as_bytes()).into_string()
        || status.new_device_peer_id != peer.to_string()
    {
        return Err(AslError::InvalidIdentity);
    }
    if status.source_device.is_some() && !status.old_device_revocation_authorized {
        return Err(AslError::PolicyDenied);
    }
    let unverified_legacy = is_unverified_legacy_migration(status);
    if !status.source_directory_verified && !unverified_legacy {
        return Err(AslError::PolicyDenied);
    }
    if unverified_legacy
        && !matches!(
            status.phase,
            migration::IdentityMigrationPhaseV1::ReadyForOnboarding
                | migration::IdentityMigrationPhaseV1::DirectoryRegistered
                | migration::IdentityMigrationPhaseV1::ReadyToJoin
        )
    {
        return Err(AslError::PolicyDenied);
    }
    Ok(())
}

fn is_unverified_legacy_migration(status: &IdentityMigrationStatusV1) -> bool {
    status.source_device.is_none()
        && status.source_directory.is_none()
        && !status.source_directory_verified
        && status.next_device_serial == 1
        && status.previous_revoked_serials.is_empty()
}

fn prepare_onboarding_directory(
    paths: &AppPaths,
    identity: &AgentIdentity,
    device: &DeviceIdentity,
    registry_sequence: u64,
    now_ms: u64,
) -> Result<(Vec<u8>, [u8; 32]), AslError> {
    let Some(status) = migration::status(paths)? else {
        return prepare_device_directory(identity, device, registry_sequence, now_ms);
    };
    validate_migration_onboarding(&Some(status.clone()), identity, device)?;

    let mut revoked_serials = status.previous_revoked_serials;
    let mut devices = Vec::new();
    if let Some(encoded_directory) = status.source_directory {
        let bytes = hex::decode(encoded_directory).map_err(|_| AslError::InvalidMessage)?;
        let record = decode_record(&bytes)?;
        let RecordPayload::DeviceDirectory(source_directory) = record.record.payload else {
            return Err(AslError::InvalidIdentity);
        };
        if source_directory.agent_id != identity.agent_id()
            || source_directory.revoked_serials != revoked_serials
        {
            return Err(AslError::InvalidIdentity);
        }
        for certificate in source_directory.devices {
            let is_revoked_source = status.source_device.as_ref().is_some_and(|source| {
                certificate.serial == source.certificate_serial
                    && libp2p_identity::PeerId::from_bytes(certificate.peer_id.as_bytes())
                        .is_ok_and(|peer| peer.to_string() == source.peer_id)
            });
            if is_revoked_source {
                if !status.old_device_revocation_authorized {
                    return Err(AslError::PolicyDenied);
                }
                revoked_serials.push(certificate.serial);
                continue;
            }
            if now_ms >= certificate.expires_at_ms {
                continue;
            }
            if now_ms < certificate.issued_at_ms || certificate.peer_id == device.peer_id() {
                return Err(AslError::InvalidIdentity);
            }
            verify_device_certificate(
                &certificate,
                identity.agent_id(),
                &certificate.peer_id,
                identity.controller_address(),
                1,
                now_ms,
            )?;
            devices.push(certificate);
        }
    } else if status.source_device.is_some() || status.source_directory_verified {
        return Err(AslError::InvalidIdentity);
    }
    revoked_serials.sort_unstable();
    revoked_serials.dedup();
    if revoked_serials.len() > 64 || devices.len() >= 64 {
        return Err(AslError::QuotaExceeded);
    }

    const DEVICE_CERTIFICATE_LIFETIME_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
    let certificate = identity.issue_device_certificate(
        device.peer_id(),
        status.next_device_serial,
        now_ms,
        now_ms
            .checked_add(DEVICE_CERTIFICATE_LIFETIME_MS)
            .ok_or(AslError::InvalidMessage)?,
    )?;
    devices.push(certificate);
    devices.sort_by(|left, right| left.peer_id.as_bytes().cmp(right.peer_id.as_bytes()));
    let directory = DeviceDirectory {
        agent_id: identity.agent_id(),
        registry_sequence,
        devices,
        revoked_serials,
    };
    let commitment = device_directory_commitment(&directory)?.0;
    let bytes = sign_record(
        identity,
        RecordPayload::DeviceDirectory(directory),
        1,
        now_ms,
        MAX_RECORD_LIFETIME_MS,
    )?;
    Ok((bytes, commitment))
}

fn prepare_register(
    paths: &AppPaths,
    status: &mut IdentityOnboardingStatusV1,
    identity: &AgentIdentity,
    device: &DeviceIdentity,
    deployment: RegistryDeploymentV1,
    now_ms: u64,
) -> Result<(), AslError> {
    if status.operation.as_deref() == Some("register") && resumable_draft(status, now_ms) {
        return Ok(());
    }
    let (bytes, commitment) = prepare_onboarding_directory(paths, identity, device, 1, now_ms)?;
    let request =
        IdentityRegistrationRequest::build(identity, deployment, commitment, default_deadline()?)?;
    set_draft(status, "register", 1, commitment, &bytes, &request);
    persist_status(paths, status, now_ms)
}

fn open_chain(
    mut network: NetworkIdentityConfigurationV1,
    database: &Path,
) -> Result<
    (
        NetworkIdentityConfigurationV1,
        ChainHttpClient,
        tokio::runtime::Runtime,
        DurableIdentityResolver,
    ),
    AslError,
> {
    let store = open_store(database)?;
    let http = ChainHttpClient::new(network.http.clone()).map_err(|_| AslError::InvalidIdentity)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| AslError::SandboxUnavailable)?;
    checkpoint_access::prepare_startup(&mut network, database, &store, &http, &runtime)?;
    let resolver = if store
        .chain_checkpoint_hash(network.resolver.consensus.chain_id)?
        .is_some()
    {
        DurableIdentityResolver::restore(store, network.resolver.clone(), unix_time_secs()?)
            .map_err(|_| AslError::InvalidIdentity)?
    } else {
        let now = unix_time_secs()?;
        let client = runtime
            .block_on(http.bootstrap(network.resolver.consensus.clone(), now))
            .map_err(|_| AslError::InvalidIdentity)?;
        DurableIdentityResolver::create(store, network.resolver.clone(), client, now)
            .map_err(|_| AslError::InvalidIdentity)?
    };
    Ok((network, http, runtime, resolver))
}

fn emit_revocation_hook(
    paths: &AppPaths,
    status: &IdentityOnboardingStatusV1,
) -> Result<(), AslError> {
    let store = open_store(&paths.existing_state_database()?)?;
    let value = serde_json::to_string(&json!({
        "schema": "asl-finalized-revocation-hook-v1",
        "agent_id": status.agent_id,
        "chain_id": status.chain_id,
        "registry": status.registry,
        "sequence": status.registry_sequence,
        "transaction_hash": status.transaction_hash,
        "action": "suspend_admission_and_refresh_verified_proofs"
    }))
    .map_err(|_| AslError::InvalidMessage)?;
    let updated_at_ms = i64::try_from(unix_time_ms()?).map_err(|_| AslError::InvalidMessage)?;
    store.set_setting("identity.finalized_revocation_v1", &value, updated_at_ms)
}

fn prepare_update(
    paths: &AppPaths,
    status: &mut IdentityOnboardingStatusV1,
    identity: &AgentIdentity,
    device: &DeviceIdentity,
    deployment: RegistryDeploymentV1,
    sequence: u64,
    now_ms: u64,
) -> Result<(), AslError> {
    if status.operation.as_deref() == Some("update")
        && status.registry_sequence == sequence
        && resumable_draft(status, now_ms)
    {
        return Ok(());
    }
    let (bytes, commitment) =
        prepare_onboarding_directory(paths, identity, device, sequence, now_ms)?;
    let request = IdentityRegistrationRequest::build_update(
        identity,
        deployment,
        commitment,
        sequence,
        default_deadline()?,
    )?;
    set_draft(status, "update", sequence, commitment, &bytes, &request);
    persist_status(paths, status, now_ms)
}

fn set_draft(
    status: &mut IdentityOnboardingStatusV1,
    operation: &str,
    sequence: u64,
    commitment: [u8; 32],
    bytes: &[u8],
    request: &IdentityRegistrationRequest,
) {
    status.phase = OnboardingPhaseV1::Prepared;
    status.operation = Some(operation.into());
    status.registry_sequence = sequence;
    status.state_commitment = hex32(commitment);
    status.transaction_hash = None;
    status.submission_route = None;
    status.directory_published = false;
    status.last_error = None;
    status.draft = Some(draft(
        operation,
        sequence,
        commitment,
        bytes,
        serde_json::to_value(request).unwrap_or(Value::Null),
        request.deadline,
    ));
}

fn draft(
    operation: &str,
    sequence: u64,
    commitment: [u8; 32],
    bytes: &[u8],
    request: Value,
    deadline: u64,
) -> OnboardingDraftV1 {
    OnboardingDraftV1 {
        operation: operation.into(),
        registry_sequence: sequence,
        state_commitment: hex32(commitment),
        signed_directory: hex::encode(bytes),
        request,
        deadline,
    }
}

fn resumable_draft(status: &IdentityOnboardingStatusV1, now_ms: u64) -> bool {
    status.draft.as_ref().is_some_and(|draft| {
        draft.deadline > now_ms / 1000
            && !matches!(
                status.phase,
                OnboardingPhaseV1::DirectoryInstalled | OnboardingPhaseV1::ReadyToJoin
            )
    })
}

fn wait_for_finality(
    paths: &AppPaths,
    config: &IdentityOnboardingConfigV1,
    runtime: &tokio::runtime::Runtime,
    http: &ChainHttpClient,
    resolver: &mut DurableIdentityResolver,
    status: &mut IdentityOnboardingStatusV1,
    agent: asl_types::ids::AgentId,
) -> Result<(), AslError> {
    let deadline = Instant::now() + Duration::from_secs(config.finality_timeout_seconds);
    loop {
        let now = unix_time_secs()?;
        let resolution = refresh_resolution(runtime, http, resolver, agent, now)?;
        match resolution {
            IdentityResolution::Verified(verified)
                if verified.state().status == RegistryStatus::Active
                    && verified.state().sequence == status.registry_sequence
                    && hex32(verified.state().state_commitment) == status.state_commitment =>
            {
                return Ok(());
            }
            IdentityResolution::Limited(crate::chain::LimitedReason::Revoked) => {
                status.phase = OnboardingPhaseV1::Revoked;
                persist_status(paths, status, unix_time_ms()?)?;
                return Err(AslError::InvalidIdentity);
            }
            _ => {}
        }
        if Instant::now() >= deadline {
            status.last_error = Some("finality wait timed out".into());
            persist_status(paths, status, unix_time_ms()?)?;
            return Err(AslError::ExpiredMessage);
        }
        std::thread::sleep(Duration::from_secs(config.finality_poll_seconds));
    }
}

fn refresh_resolution(
    runtime: &tokio::runtime::Runtime,
    http: &ChainHttpClient,
    resolver: &mut DurableIdentityResolver,
    agent: asl_types::ids::AgentId,
    now: u64,
) -> Result<IdentityResolution, AslError> {
    runtime
        .block_on(http.synchronize(resolver, now))
        .map_err(|_| AslError::InvalidIdentity)?;
    let now = unix_time_secs()?;
    runtime
        .block_on(http.fetch_identity(resolver, agent, now))
        .map_err(|_| AslError::InvalidIdentity)?;
    Ok(resolver.resolve(agent, unix_time_secs()?))
}

fn submit_registration(
    config: &SubmissionConfigV1,
    http: &crate::chain::ChainHttpConfigV1,
    draft: &OnboardingDraftV1,
) -> Result<(String, SubmissionRouteV1), AslError> {
    if matches!(
        config.mode,
        SubmissionModeV1::Sponsor | SubmissionModeV1::Fallback
    ) {
        for sponsor in &config.sponsors {
            if let Ok(hash) = submit_to_sponsor(sponsor, draft) {
                return Ok((hash, SubmissionRouteV1::Sponsor));
            }
        }
    }
    if matches!(
        config.mode,
        SubmissionModeV1::SelfPay | SubmissionModeV1::Fallback
    ) {
        let signer = config.self_pay.as_ref().ok_or(AslError::InvalidIdentity)?;
        if let Ok(hash) = submit_with_external_signer(signer, http, draft) {
            return Ok((hash, SubmissionRouteV1::SelfPay));
        }
    }
    Err(AslError::PolicyDenied)
}

fn submit_to_sponsor(
    sponsor: &SponsorEndpointV1,
    draft: &OnboardingDraftV1,
) -> Result<String, AslError> {
    let url = validated_url(&sponsor.url, sponsor.allow_loopback_http)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| AslError::SandboxUnavailable)?;
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .map_err(|_| AslError::SandboxUnavailable)?;
    let body = runtime.block_on(async {
        let response = client
            .post(url)
            .json(&json!({
                "schema": "asl-identity-sponsor-request-v1",
                "operation": draft.operation,
                "registry_sequence": draft.registry_sequence,
                "request": draft.request
            }))
            .send()
            .await
            .map_err(|_| AslError::SandboxUnavailable)?;
        if !response.status().is_success() {
            return Err(AslError::PolicyDenied);
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| AslError::InvalidMessage)?;
        if bytes.len() > SPONSOR_RESPONSE_MAX_BYTES {
            return Err(AslError::InvalidMessage);
        }
        Ok(bytes)
    })?;
    transaction_hash_from_json(&body)
}

fn submit_with_external_signer(
    signer: &SelfPaySignerV1,
    http: &crate::chain::ChainHttpConfigV1,
    draft: &OnboardingDraftV1,
) -> Result<String, AslError> {
    if !signer.executable.is_absolute() {
        return Err(AslError::InvalidIdentity);
    }
    let mut child = Command::new(&signer.executable)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let input = serde_json::to_vec(&json!({
        "schema": "asl-self-pay-sign-v1",
        "operation": draft.operation,
        "registry_sequence": draft.registry_sequence,
        "request": draft.request
    }))
    .map_err(|_| AslError::InvalidMessage)?;
    child
        .stdin
        .take()
        .ok_or(AslError::SandboxUnavailable)?
        .write_all(&input)?;
    let output = child.wait_with_output()?;
    if !output.status.success() || output.stdout.len() > SIGNER_RESPONSE_MAX_BYTES {
        return Err(AslError::PolicyDenied);
    }
    let value: Value =
        serde_json::from_slice(&output.stdout).map_err(|_| AslError::InvalidMessage)?;
    if let Some(hash) = transaction_hash_value(&value) {
        return Ok(hash);
    }
    let raw = value
        .get("raw_transaction")
        .and_then(Value::as_str)
        .ok_or(AslError::InvalidMessage)?;
    submit_raw_transaction(http, raw)
}

fn submit_raw_transaction(
    config: &crate::chain::ChainHttpConfigV1,
    raw_transaction: &str,
) -> Result<String, AslError> {
    let raw = raw_transaction
        .strip_prefix("0x")
        .unwrap_or(raw_transaction);
    if raw.is_empty()
        || !raw.len().is_multiple_of(2)
        || raw.len() > RAW_TRANSACTION_MAX_BYTES
        || hex::decode(raw).is_err()
    {
        return Err(AslError::InvalidMessage);
    }
    let endpoint = config
        .execution_endpoints
        .first()
        .ok_or(AslError::InvalidIdentity)?;
    let url = validated_url(&endpoint.url, endpoint.allow_loopback_http)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| AslError::SandboxUnavailable)?;
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .map_err(|_| AslError::SandboxUnavailable)?;
    let bytes = runtime.block_on(async {
        let response = client
            .post(url)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": "asl-identity-onboarding",
                "method": "eth_sendRawTransaction",
                "params": [format!("0x{raw}")]
            }))
            .send()
            .await
            .map_err(|_| AslError::SandboxUnavailable)?;
        if !response.status().is_success() {
            return Err(AslError::PolicyDenied);
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| AslError::InvalidMessage)?;
        if bytes.len() > SPONSOR_RESPONSE_MAX_BYTES {
            return Err(AslError::InvalidMessage);
        }
        Ok(bytes)
    })?;
    transaction_hash_from_json(&bytes)
}

fn transaction_hash_from_json(bytes: &[u8]) -> Result<String, AslError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| AslError::InvalidMessage)?;
    if value.get("error").is_some() {
        return Err(AslError::PolicyDenied);
    }
    transaction_hash_value(&value).ok_or(AslError::InvalidMessage)
}

fn transaction_hash_value(value: &Value) -> Option<String> {
    ["transaction_hash", "tx_hash"]
        .into_iter()
        .find_map(|key| value.get(key).and_then(Value::as_str))
        .or_else(|| value.get("result").and_then(Value::as_str))
        .filter(|hash| valid_hash(hash))
        .map(|hash| {
            let hash = hash.strip_prefix("0x").unwrap_or(hash);
            format!("0x{}", hash.to_ascii_lowercase())
        })
}

fn valid_hash(value: &str) -> bool {
    let value = value.strip_prefix("0x").unwrap_or(value);
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validated_url(value: &str, allow_loopback_http: bool) -> Result<Url, AslError> {
    let url = Url::parse(value).map_err(|_| AslError::InvalidIdentity)?;
    let loopback = url
        .host_str()
        .and_then(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().ok())
        .is_some_and(|address| address.is_loopback());
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || (url.scheme() != "https" && !(url.scheme() == "http" && loopback && allow_loopback_http))
    {
        return Err(AslError::InvalidIdentity);
    }
    Ok(url)
}

fn install_directory(path: &Path, bytes: &[u8]) -> Result<(), AslError> {
    let record = decode_record(bytes)?;
    let RecordPayload::DeviceDirectory(directory) = record.record.payload else {
        return Err(AslError::InvalidDeviceCertificate);
    };
    let _ = device_directory_commitment(&directory)?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub(crate) fn verify_signed_directory(
    bytes: &[u8],
    expected_agent: asl_types::ids::AgentId,
    expected_sequence: u64,
    expected_commitment: [u8; 32],
) -> Result<(), AslError> {
    let record = decode_record(bytes)?;
    let RecordPayload::DeviceDirectory(directory) = record.record.payload else {
        return Err(AslError::InvalidDeviceCertificate);
    };
    if directory.agent_id != expected_agent
        || directory.registry_sequence != expected_sequence
        || device_directory_commitment(&directory)?.0 != expected_commitment
    {
        return Err(AslError::InvalidIdentity);
    }
    Ok(())
}

fn load_status(
    path: &Path,
    expected_agent: [u8; 32],
    deployment: RegistryDeploymentV1,
) -> Result<Option<IdentityOnboardingStatusV1>, AslError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if bytes.len() as u64 > STATUS_MAX_BYTES {
        return Err(AslError::InvalidIdentity);
    }
    let status: IdentityOnboardingStatusV1 =
        serde_json::from_slice(&bytes).map_err(|_| AslError::InvalidIdentity)?;
    if status.version != 1
        || status.agent_id != format!("0x{}", hex::encode(expected_agent))
        || status.chain_id != deployment.chain_id
        || status.registry != format!("0x{}", hex::encode(deployment.address))
    {
        return Err(AslError::InvalidIdentity);
    }
    Ok(Some(status))
}

fn persist_status(
    paths: &AppPaths,
    status: &mut IdentityOnboardingStatusV1,
    now_ms: u64,
) -> Result<(), AslError> {
    status.updated_at_ms = now_ms;
    let bytes = serde_json::to_vec(status).map_err(|_| AslError::InvalidMessage)?;
    if bytes.len() as u64 > STATUS_MAX_BYTES {
        return Err(AslError::QuotaExceeded);
    }
    let path = paths.identity_onboarding_status();
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

fn new_status(
    identity: &AgentIdentity,
    deployment: RegistryDeploymentV1,
    now_ms: u64,
) -> IdentityOnboardingStatusV1 {
    IdentityOnboardingStatusV1 {
        version: 1,
        agent_id: format!("0x{}", hex::encode(identity.agent_id().as_bytes())),
        chain_id: deployment.chain_id,
        registry: format!("0x{}", hex::encode(deployment.address)),
        phase: OnboardingPhaseV1::Prepared,
        operation: None,
        registry_sequence: 0,
        state_commitment: String::new(),
        draft: None,
        transaction_hash: None,
        submission_route: None,
        directory_published: false,
        last_error: None,
        updated_at_ms: now_ms,
    }
}

fn read_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>, AslError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > max_bytes {
        return Err(AslError::InvalidIdentity);
    }
    Ok(fs::read(path)?)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, AslError> {
    hex::decode(value).map_err(|_| AslError::InvalidMessage)
}

fn hex32(value: [u8; 32]) -> String {
    format!("0x{}", hex::encode(value))
}

fn unix_time_secs() -> Result<u64, AslError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| AslError::ExpiredMessage)
}

fn unix_time_ms() -> Result<u64, AslError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or(AslError::ExpiredMessage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_distinguishes_sponsor_self_pay_and_fallback() {
        let sponsor = SponsorEndpointV1 {
            url: "https://sponsor.invalid/relay".into(),
            allow_loopback_http: false,
        };
        assert!(
            IdentityOnboardingConfigV1 {
                version: 1,
                submission: SubmissionConfigV1 {
                    mode: SubmissionModeV1::Sponsor,
                    sponsors: vec![sponsor.clone()],
                    self_pay: None,
                },
                finality_timeout_seconds: 60,
                finality_poll_seconds: 1,
                publication_timeout_seconds: 30,
            }
            .validate()
            .is_ok()
        );
        assert!(
            IdentityOnboardingConfigV1 {
                version: 1,
                submission: SubmissionConfigV1 {
                    mode: SubmissionModeV1::SelfPay,
                    sponsors: Vec::new(),
                    self_pay: Some(SelfPaySignerV1 {
                        executable: PathBuf::from("relative-signer.exe"),
                    }),
                },
                finality_timeout_seconds: 60,
                finality_poll_seconds: 1,
                publication_timeout_seconds: 30,
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn sponsor_and_rpc_hashes_are_normalized_and_untrusted_fields_are_ignored() {
        let hash = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert_eq!(
            transaction_hash_from_json(
                format!(r#"{{"transaction_hash":"{hash}","unexpected":true}}"#).as_bytes()
            )
            .unwrap(),
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert!(transaction_hash_from_json(br#"{"transaction_hash":"0x1234"}"#).is_err());
    }

    #[test]
    fn status_is_bound_to_the_exact_agent_and_registry_deployment() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("status.json");
        let identity = AgentIdentity::generate().unwrap();
        let deployment = RegistryDeploymentV1 {
            version: 1,
            chain_id: 7,
            address: [9; 20],
            runtime_code_hash: [8; 32],
        };
        let status = new_status(&identity, deployment, 10);
        fs::write(&path, serde_json::to_vec(&status).unwrap()).unwrap();
        assert_eq!(
            load_status(&path, *identity.agent_id().as_bytes(), deployment)
                .unwrap()
                .unwrap(),
            status
        );
        let mut wrong = deployment;
        wrong.chain_id = 8;
        assert!(load_status(&path, *identity.agent_id().as_bytes(), wrong).is_err());
    }

    #[test]
    fn expired_or_completed_drafts_are_not_resumed() {
        let identity = AgentIdentity::generate().unwrap();
        let mut status = new_status(
            &identity,
            RegistryDeploymentV1 {
                version: 1,
                chain_id: 1,
                address: [3; 20],
                runtime_code_hash: [4; 32],
            },
            0,
        );
        status.operation = Some("register".into());
        status.draft = Some(draft("register", 1, [5; 32], b"directory", Value::Null, 20));
        assert!(resumable_draft(&status, 10_000));
        assert!(!resumable_draft(&status, 25_000));
        status.phase = OnboardingPhaseV1::DirectoryInstalled;
        assert!(!resumable_draft(&status, 10_000));
    }

    #[test]
    fn publication_verification_binds_agent_sequence_and_commitment() {
        let identity = AgentIdentity::generate().unwrap();
        let device = DeviceIdentity::generate().unwrap();
        let (bytes, commitment) = prepare_device_directory(&identity, &device, 3, 1_000).unwrap();
        verify_signed_directory(&bytes, identity.agent_id(), 3, commitment).unwrap();
        assert!(verify_signed_directory(&bytes, identity.agent_id(), 4, commitment).is_err());
        let mut wrong = commitment;
        wrong[0] ^= 1;
        assert!(verify_signed_directory(&bytes, identity.agent_id(), 3, wrong).is_err());
    }
}
