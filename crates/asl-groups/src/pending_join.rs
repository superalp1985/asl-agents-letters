//! Local DPAPI snapshot for one approved invitation, not an identity export.

use asl_policy::{protect_secret, unprotect_secret};
use asl_store::group_state::{MAX_SEALED_ROOM_BYTES, MlsIncomingInvite, MlsJoinKey};
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128},
    protocol::{GroupBody, GroupMembership, GroupPacket},
};
use openmls::prelude::{
    CredentialWithKey, KeyPackage, KeyPackageBundle, MlsMessageOut, OpenMlsProvider,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::storage::StorageProvider as _;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use zeroize::Zeroizing;

use crate::membership::{GROUP_CIPHERSUITE, read_key_package};

const FORMAT: &str = "ASL-MLS-PENDING-JOIN-v1";

#[derive(Deserialize, Eq, PartialEq, Serialize)]
struct JoinScope {
    room: Hash32,
    invite: Id128,
    request: Id128,
    package: Hash32,
    epoch: u64,
    inviter: AgentId,
    inviter_device: ByteBuf,
    recipient: AgentId,
    recipient_device: ByteBuf,
    expires_at_ms: u64,
}

impl JoinScope {
    fn new(invite: &MlsIncomingInvite, key: MlsJoinKey) -> Self {
        Self {
            room: invite.wire_id,
            invite: invite.id,
            request: key.request_id,
            package: key.package_ref,
            epoch: invite.base_epoch,
            inviter: invite.inviter,
            inviter_device: invite.inviter_device.as_bytes().to_vec().into(),
            recipient: invite.recipient,
            recipient_device: invite.recipient_device.as_bytes().to_vec().into(),
            expires_at_ms: invite.expires_at_ms,
        }
    }

    fn request(&self, bundle: &KeyPackageBundle) -> Result<GroupPacket, AslError> {
        let message = MlsMessageOut::from(bundle.key_package().clone())
            .to_bytes()
            .map_err(|_| AslError::InvalidPolicyState)?;
        let request = GroupPacket {
            message_id: self.request,
            group_id: self.room,
            epoch: self.epoch,
            body: GroupBody::Membership(GroupMembership::KeyPackage {
                invite: self.invite,
                message,
            }),
        };
        request.validate_request()?;
        Ok(request)
    }
}

#[derive(Deserialize, Serialize)]
struct SealedJoin<F, K, S> {
    format: F,
    scope: JoinScope,
    bundle: K,
    signer: S,
}

pub struct PreparedJoin {
    pub key: MlsJoinKey,
    pub sealed_package: Vec<u8>,
}

/// Only after local approval. Core supplies the room-bound identity
/// credential and a fresh signing key, then commits the returned state.
pub fn prepare(
    invite: &MlsIncomingInvite,
    request_id: Id128,
    credential: CredentialWithKey,
    signer: &SignatureKeyPair,
) -> Result<PreparedJoin, AslError> {
    let provider = OpenMlsRustCrypto::default();
    let bundle = KeyPackage::builder()
        .build(GROUP_CIPHERSUITE, &provider, signer, credential)
        .map_err(|_| AslError::InvalidPolicyState)?;
    let reference = bundle
        .key_package()
        .hash_ref(provider.crypto())
        .map_err(|_| AslError::InvalidPolicyState)?;
    let key = MlsJoinKey {
        request_id,
        package_ref: Hash32(
            reference
                .as_slice()
                .try_into()
                .map_err(|_| AslError::InvalidPolicyState)?,
        ),
    };
    let scope = JoinScope::new(invite, key);
    read_key_package(&scope.request(&bundle)?, provider.crypto())?;
    let snapshot = SealedJoin {
        format: FORMAT,
        scope,
        bundle,
        signer,
    };
    let bytes = Zeroizing::new(cbor2::to_vec(&snapshot).map_err(|_| AslError::InvalidPolicyState)?);
    let sealed_package = protect_secret(&bytes)?;
    if sealed_package.len() > MAX_SEALED_ROOM_BYTES {
        return Err(AslError::QuotaExceeded);
    }
    Ok(PreparedJoin {
        key,
        sealed_package,
    })
}

/// Restore only a live approved row from Store. Every attempt gets a new
/// provider: staging a Welcome consumes its copy of the KeyPackage.
pub fn restore(
    invite: &MlsIncomingInvite,
    key: MlsJoinKey,
    sealed_package: &[u8],
) -> Result<(GroupPacket, OpenMlsRustCrypto), AslError> {
    if !(1..=MAX_SEALED_ROOM_BYTES).contains(&sealed_package.len()) {
        return Err(AslError::InvalidDatabase);
    }
    let bytes = unprotect_secret(sealed_package)?;
    cbor2::validate_slice(&bytes).map_err(|_| AslError::InvalidDatabase)?;
    let snapshot: SealedJoin<String, KeyPackageBundle, SignatureKeyPair> =
        cbor2::from_slice(&bytes).map_err(|_| AslError::InvalidDatabase)?;
    if snapshot.format != FORMAT || snapshot.scope != JoinScope::new(invite, key) {
        return Err(AslError::InvalidDatabase);
    }
    let provider = OpenMlsRustCrypto::default();
    let request = snapshot.scope.request(&snapshot.bundle)?;
    let (package, reference) = read_key_package(&request, provider.crypto())?;
    if reference != key.package_ref
        || package.leaf_node().signature_key().as_slice() != snapshot.signer.public()
    {
        return Err(AslError::InvalidDatabase);
    }
    let storage_ref = package
        .hash_ref(provider.crypto())
        .map_err(|_| AslError::InvalidDatabase)?;
    provider
        .storage()
        .write_key_package(&storage_ref, &snapshot.bundle)
        .map_err(|_| AslError::InvalidDatabase)?;
    snapshot
        .signer
        .store(provider.storage())
        .map_err(|_| AslError::InvalidDatabase)?;
    Ok((request, provider))
}
