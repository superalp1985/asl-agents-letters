//! Decode MLS objects without granting ASL room membership. Use a disposable
//! provider for candidate processing until identity, policy and storage agree.

mod origin;
pub use origin::RoomOrigin;
pub(crate) use origin::{ORIGIN_CAPABILITY, room_leaf_capabilities};

use asl_types::{
    error::AslError,
    ids::Hash32,
    protocol::{GroupBody, GroupMembership, GroupPacket, MAX_GROUP_MEMBERS},
};
use openmls::{
    framing::ContentType,
    prelude::{
        Ciphersuite, KeyPackage, MlsGroup, MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn,
        OpenMlsCrypto, OpenMlsProvider, ProtocolMessage, ProtocolVersion, StagedWelcome,
        WireFormat,
        tls_codec::{Deserialize as _, DeserializeBytes as _},
    },
};

pub const GROUP_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Compare one epoch without putting the raw MLS epoch authenticator on the wire.
pub fn sync_epoch_binding(
    group: &MlsGroup,
    crypto: &impl OpenMlsCrypto,
) -> Result<Hash32, AslError> {
    group
        .export_secret(crypto, "ASL group sync binding v1", &[], Hash32::LENGTH)
        .map_err(|_| AslError::InvalidPolicyState)?
        .try_into()
        .map(Hash32)
        .map_err(|_| AslError::InvalidPolicyState)
}

/// Verify the OpenMLS package and compute its RFC 9420 reference. Core still
/// matches the invite and verifies the leaf against the admitted device.
pub fn read_key_package(
    packet: &GroupPacket,
    crypto: &impl OpenMlsCrypto,
) -> Result<(KeyPackage, Hash32), AslError> {
    packet.validate_request()?;
    let GroupBody::Membership(GroupMembership::KeyPackage { message, .. }) = &packet.body else {
        return Err(AslError::InvalidMessage);
    };
    let MlsMessageBodyIn::KeyPackage(package) = read_mls(message)?.extract() else {
        return Err(AslError::InvalidMessage);
    };
    let package = package
        .validate(crypto, ProtocolVersion::Mls10)
        .map_err(|_| AslError::InvalidMessage)?;
    if package.ciphersuite() != GROUP_CIPHERSUITE || package.last_resort() {
        return Err(AslError::InvalidMessage);
    }
    let reference = package
        .hash_ref(crypto)
        .map_err(|_| AslError::InvalidMessage)?;
    let reference = reference
        .as_slice()
        .try_into()
        .map_err(|_| AslError::InvalidMessage)?;
    Ok((package, Hash32(reference)))
}

/// Only call after local consent and connection matching. `expected_ref`
/// comes from the locally generated package, not the response. Do not install
/// the result until Core has bound the signer and tree leaves to ASL identity.
pub fn stage_welcome(
    request: &GroupPacket,
    reply: &GroupPacket,
    expected_ref: Hash32,
    candidate: &impl OpenMlsProvider,
) -> Result<StagedWelcome, AslError> {
    request.match_reply(reply)?;
    let GroupBody::Membership(GroupMembership::Welcome {
        package_ref,
        message,
        ..
    }) = &reply.body
    else {
        return Err(AslError::InvalidMessage);
    };
    if *package_ref != expected_ref {
        return Err(AslError::InvalidMessage);
    }
    let (package, request_ref) = read_key_package(request, candidate.crypto())?;
    if request_ref != expected_ref {
        return Err(AslError::InvalidMessage);
    }
    let MlsMessageBodyIn::Welcome(welcome) = read_mls(message)?.extract() else {
        return Err(AslError::InvalidMessage);
    };
    if welcome.ciphersuite() != GROUP_CIPHERSUITE
        || !matches!(welcome.secrets(), [secret] if secret.new_member().as_slice() == expected_ref.as_bytes())
    {
        return Err(AslError::InvalidMessage);
    }
    let staged = StagedWelcome::new_from_welcome(
        candidate,
        &MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build(),
        welcome,
        None,
    )
    .map_err(|_| AslError::InvalidMessage)?;
    let context = staged.group_context();
    if context.protocol_version() != ProtocolVersion::Mls10
        || context.ciphersuite() != GROUP_CIPHERSUITE
        || context.group_id().as_slice() != reply.group_id.as_bytes()
        || context.epoch().as_u64() != reply.epoch
        || staged.own_leaf_node() != Some(package.leaf_node())
        || staged.members().take(MAX_GROUP_MEMBERS + 1).count() > MAX_GROUP_MEMBERS
    {
        return Err(AslError::InvalidMessage);
    }
    Ok(staged)
}

/// A correctly framed result still needs authenticated processing by the
/// caller's OpenMLS candidate group, followed by ASL identity and policy checks.
pub fn read_group_message(packet: &GroupPacket) -> Result<ProtocolMessage, AslError> {
    packet.validate_request()?;
    let (bytes, kind) = match &packet.body {
        GroupBody::Application(bytes) => (bytes, ContentType::Application),
        GroupBody::Membership(GroupMembership::Commit(bytes)) => (bytes, ContentType::Commit),
        _ => return Err(AslError::InvalidMessage),
    };
    private_message(packet, bytes, kind)
}

pub fn read_sync_commit(
    request: &GroupPacket,
    reply: &GroupPacket,
) -> Result<ProtocolMessage, AslError> {
    request.match_reply(reply)?;
    let GroupBody::Membership(GroupMembership::SyncCommit(bytes)) = &reply.body else {
        return Err(AslError::InvalidMessage);
    };
    private_message(reply, bytes, ContentType::Commit)
}

fn private_message(
    packet: &GroupPacket,
    bytes: &[u8],
    kind: ContentType,
) -> Result<ProtocolMessage, AslError> {
    let message = read_mls(bytes)?
        .try_into_protocol_message()
        .map_err(|_| AslError::InvalidMessage)?;
    if message.wire_format() != WireFormat::PrivateMessage
        || message.group_id().as_slice() != packet.group_id.as_bytes()
        || message.epoch().as_u64() != packet.epoch
        || message.content_type() != kind
    {
        return Err(AslError::InvalidMessage);
    }
    Ok(message)
}

fn read_mls(bytes: &[u8]) -> Result<MlsMessageIn, AslError> {
    // OpenMLS does not expose the header version on MlsMessageIn.
    let (version, _) =
        ProtocolVersion::tls_deserialize_bytes(bytes).map_err(|_| AslError::InvalidMessage)?;
    if version != ProtocolVersion::Mls10 {
        return Err(AslError::IncompatibleVersion);
    }
    MlsMessageIn::tls_deserialize_exact(bytes).map_err(|_| AslError::InvalidMessage)
}
