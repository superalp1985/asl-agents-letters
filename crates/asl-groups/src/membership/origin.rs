use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, PeerId},
    protocol::DeviceCertificate,
};
use openmls::prelude::{
    Capabilities, Extension, ExtensionType, Extensions, GroupContext, MlsGroupCreateConfig,
    OpenMlsCrypto, OpenMlsProvider, OpenMlsRand, RequiredCapabilitiesExtension, UnknownExtension,
};

use super::GROUP_CIPHERSUITE;

const ORIGIN_EXTENSION: u16 = 0xf720;
const DOMAIN: &[u8] = b"ASL-MLS-ROOM-v1\0";
const ORIGIN_VERSION: u8 = 1;

/// The room identifier commits to its original creator device. An MLS
/// member may sign a Welcome, but cannot invent a different origin for it.
pub struct RoomOrigin {
    wire_id: Hash32,
    agent: AgentId,
    device: PeerId,
    payload: Vec<u8>,
}

impl RoomOrigin {
    pub fn generate(
        creator: &DeviceCertificate,
        provider: &impl OpenMlsProvider,
    ) -> Result<Self, AslError> {
        let nonce: [u8; 32] = provider
            .rand()
            .random_array()
            .map_err(|_| AslError::InvalidPolicyState)?;
        let mut payload = Vec::with_capacity(65 + creator.peer_id.as_bytes().len());
        payload.push(ORIGIN_VERSION);
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(creator.agent_id.as_bytes());
        payload.extend_from_slice(creator.peer_id.as_bytes());
        Self::decode(&payload, provider.crypto())
    }

    pub fn from_context(
        wire_id: Hash32,
        extensions: &Extensions<GroupContext>,
        crypto: &impl OpenMlsCrypto,
    ) -> Result<Self, AslError> {
        let payload = &extensions
            .unknown(ORIGIN_EXTENSION)
            .ok_or(AslError::InvalidMessage)?
            .0;
        let origin = Self::decode(payload, crypto)?;
        if origin.wire_id != wire_id {
            return Err(AslError::InvalidIdentity);
        }
        if !extensions.required_capabilities().is_some_and(|required| {
            required
                .extension_types()
                .contains(&ExtensionType::Unknown(ORIGIN_EXTENSION))
        }) {
            return Err(AslError::InvalidMessage);
        }
        Ok(origin)
    }

    pub fn wire_id(&self) -> Hash32 {
        self.wire_id
    }

    pub fn matches_creator(&self, certificate: &DeviceCertificate) -> bool {
        self.agent == certificate.agent_id && self.device == certificate.peer_id
    }

    pub fn group_config(&self) -> Result<MlsGroupCreateConfig, AslError> {
        let extensions = Extensions::from_vec(vec![
            Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
                &[ExtensionType::Unknown(ORIGIN_EXTENSION)],
                &[],
                &[],
            )),
            Extension::Unknown(ORIGIN_EXTENSION, UnknownExtension(self.payload.clone())),
        ])
        .map_err(|_| AslError::InvalidPolicyState)?;
        Ok(MlsGroupCreateConfig::builder()
            .ciphersuite(GROUP_CIPHERSUITE)
            .capabilities(room_leaf_capabilities())
            .with_group_context_extensions(extensions)
            .use_ratchet_tree_extension(true)
            .build())
    }

    fn decode(payload: &[u8], crypto: &impl OpenMlsCrypto) -> Result<Self, AslError> {
        let Some((prefix, peer_bytes)) = payload.split_first_chunk::<65>() else {
            return Err(AslError::InvalidMessage);
        };
        if prefix[0] != ORIGIN_VERSION || !(1..=128).contains(&peer_bytes.len()) {
            return Err(AslError::InvalidMessage);
        }
        let device =
            PeerId::from_bytes(peer_bytes.to_vec()).map_err(|_| AslError::InvalidMessage)?;
        let agent = AgentId(
            prefix[33..]
                .try_into()
                .map_err(|_| AslError::InvalidMessage)?,
        );
        let digest = crypto
            .hash(
                GROUP_CIPHERSUITE.hash_algorithm(),
                &[DOMAIN, payload].concat(),
            )
            .map_err(|_| AslError::InvalidPolicyState)?;
        let wire_id = Hash32(
            digest
                .try_into()
                .map_err(|_| AslError::InvalidPolicyState)?,
        );
        if wire_id.0 == [0; 32] || agent.0 == [0; 32] {
            return Err(AslError::InvalidIdentity);
        }
        Ok(Self {
            wire_id,
            agent,
            device,
            payload: payload.to_vec(),
        })
    }
}

pub(crate) fn room_leaf_capabilities() -> Capabilities {
    Capabilities::builder()
        .extensions(vec![ExtensionType::Unknown(ORIGIN_EXTENSION)])
        .build()
}
