use asl_net::codec::{BulkOperation, BulkRequest};
use asl_policy::{LeaseManager, PolicyService};
use asl_types::{
    error::AslError,
    ids::{Hash32, Id128, PeerId},
    manifest::{CHUNK_SIZE, MAX_MANIFEST_LEN, decode_manifest},
};

pub const MAX_INLINE_BYTES: u64 = 32 * 1024;
const MAX_CHUNK_INDEX: u32 = 65_536;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BulkReadPlan {
    Manifest {
        length: u32,
    },
    Chunk {
        offset: u64,
        length: u32,
        expected_hash: [u8; 32],
    },
    Inline {
        length: u32,
        expected_file_hash: [u8; 32],
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedBulkRequest {
    pub request_id: Id128,
    pub content_id: Hash32,
    pub plan: BulkReadPlan,
}

pub fn authorize_bulk_request<S: PolicyService>(
    policy: &S,
    leases: &LeaseManager,
    peer_id: &PeerId,
    request: &BulkRequest,
    manifest_bytes: &[u8],
    now_ms: u64,
) -> Result<AuthorizedBulkRequest, AslError> {
    if request.operation != BulkOperation::Chunk && request.chunk_index != 0 {
        return Err(AslError::NotFound);
    }
    if manifest_bytes.len() > MAX_MANIFEST_LEN {
        return Err(AslError::NotFound);
    }
    let access = leases.validate(
        policy,
        request.lease_id,
        peer_id,
        request.content_id,
        now_ms,
    )?;
    let manifest =
        decode_manifest(manifest_bytes, request.content_id.0).map_err(|_| AslError::NotFound)?;
    if manifest.file_size != access.file_size {
        return Err(AslError::NotFound);
    }

    let plan = match request.operation {
        BulkOperation::Manifest => BulkReadPlan::Manifest {
            length: u32::try_from(manifest_bytes.len()).map_err(|_| AslError::NotFound)?,
        },
        BulkOperation::Chunk => {
            if request.chunk_index >= MAX_CHUNK_INDEX
                || usize::try_from(request.chunk_index).map_err(|_| AslError::NotFound)?
                    >= manifest.chunk_hashes.len()
            {
                return Err(AslError::NotFound);
            }
            let chunk_index =
                usize::try_from(request.chunk_index).map_err(|_| AslError::NotFound)?;
            let offset = u64::from(request.chunk_index) * u64::from(CHUNK_SIZE);
            let length = manifest
                .file_size
                .checked_sub(offset)
                .ok_or(AslError::NotFound)?
                .min(u64::from(CHUNK_SIZE));
            BulkReadPlan::Chunk {
                offset,
                length: u32::try_from(length).map_err(|_| AslError::NotFound)?,
                expected_hash: manifest.chunk_hashes[chunk_index],
            }
        }
        BulkOperation::Inline => {
            if manifest.file_size > MAX_INLINE_BYTES {
                return Err(AslError::NotFound);
            }
            BulkReadPlan::Inline {
                length: u32::try_from(manifest.file_size).map_err(|_| AslError::NotFound)?,
                expected_file_hash: manifest.file_hash,
            }
        }
    };
    Ok(AuthorizedBulkRequest {
        request_id: request.request_id,
        content_id: request.content_id,
        plan,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use super::*;
    use asl_policy::{
        AccessOperation, AccessRequest, Audience, AuthenticatedDevice, GrantPolicy, LeaseManager,
        ModelPolicy, PolicyEngine, PolicyRevision, PolicySnapshot, Principal, ResourceOrigin,
        ResourcePolicy,
    };
    use asl_types::{
        manifest::{Manifest, content_id, encode_manifest},
        task::{GrantId, ResourceKey},
    };

    const NOW: u64 = 1_000_000;

    fn peer() -> PeerId {
        let mut bytes = vec![0, 36, 8, 1, 18, 32];
        bytes.extend_from_slice(&[1; 32]);
        PeerId::from_bytes(bytes).unwrap()
    }

    fn setup() -> (PolicyEngine, LeaseManager, Vec<u8>, Hash32) {
        let file_size = u64::from(CHUNK_SIZE) + 1;
        let manifest = encode_manifest(&Manifest {
            file_size,
            file_hash: [9; 32],
            chunk_hashes: vec![[1; 32], [2; 32]],
        })
        .unwrap();
        let content = Hash32(content_id(&manifest));
        let grant = GrantId(Id128([1; 16]));
        let resource = ResourceKey(Id128([2; 16]));
        let agent = asl_types::ids::AgentId([3; 32]);
        let mut grants = HashMap::new();
        grants.insert(
            grant.clone(),
            GrantPolicy {
                epoch: 1,
                active: true,
                audience: Audience::Public,
                model_policy: ModelPolicy::Never,
                extensions: HashSet::from([".bin".into()]),
                max_snapshot_bytes: file_size,
                allowed_operations: HashSet::from([AccessOperation::ReadChunk]),
                allow_derived_disclosure: false,
            },
        );
        let mut resources = HashMap::new();
        resources.insert(
            resource,
            ResourcePolicy {
                content_id: content,
                grant_id: grant,
                grant_epoch: 1,
                active: true,
                snapshot_ready: true,
                file_size,
                extension: ".bin".into(),
                retention_until_ms: None,
                origin: ResourceOrigin::Local,
            },
        );
        let snapshot = PolicySnapshot {
            revision: PolicyRevision(1),
            grants,
            resources,
            devices: HashMap::from([(
                peer(),
                AuthenticatedDevice {
                    agent_id: agent,
                    active: true,
                    chain_valid_until_ms: NOW + 120_000,
                    certificate_valid_until_ms: NOW + 120_000,
                },
            )]),
            ..PolicySnapshot::default()
        };
        (
            PolicyEngine::new(snapshot, 60_000).unwrap(),
            LeaseManager::new(),
            manifest,
            content,
        )
    }

    fn request(
        operation: BulkOperation,
        content: Hash32,
        lease: Hash32,
        index: u32,
    ) -> BulkRequest {
        BulkRequest {
            operation,
            request_id: Id128([7; 16]),
            content_id: content,
            lease_id: lease,
            chunk_index: index,
        }
    }

    #[test]
    fn authorized_plan_derives_manifest_and_exact_chunk_range() {
        let (engine, leases, manifest, content) = setup();
        let scope = engine.for_peer(peer());
        let permit = scope
            .authorize(
                &AccessRequest {
                    grant_id: GrantId(Id128([1; 16])),
                    resource_key: ResourceKey(Id128([2; 16])),
                    principal: Principal::Agent(asl_types::ids::AgentId([3; 32])),
                    operation: AccessOperation::ReadChunk,
                },
                NOW,
            )
            .unwrap();
        let lease = leases
            .issue(&scope, &permit, u64::from(CHUNK_SIZE) + 1, NOW)
            .unwrap();

        let manifest_plan = authorize_bulk_request(
            &scope,
            &leases,
            &peer(),
            &request(BulkOperation::Manifest, content, lease.lease_id, 0),
            &manifest,
            NOW,
        )
        .unwrap();
        assert_eq!(
            manifest_plan.plan,
            BulkReadPlan::Manifest {
                length: manifest.len() as u32
            }
        );

        let chunk_plan = authorize_bulk_request(
            &scope,
            &leases,
            &peer(),
            &request(BulkOperation::Chunk, content, lease.lease_id, 1),
            &manifest,
            NOW,
        )
        .unwrap();
        assert_eq!(
            chunk_plan.plan,
            BulkReadPlan::Chunk {
                offset: u64::from(CHUNK_SIZE),
                length: 1,
                expected_hash: [2; 32]
            }
        );
    }

    #[test]
    fn invalid_chunk_and_oversized_inline_are_not_found() {
        let (engine, leases, manifest, content) = setup();
        let scope = engine.for_peer(peer());
        let permit = scope
            .authorize(
                &AccessRequest {
                    grant_id: GrantId(Id128([1; 16])),
                    resource_key: ResourceKey(Id128([2; 16])),
                    principal: Principal::Agent(asl_types::ids::AgentId([3; 32])),
                    operation: AccessOperation::ReadChunk,
                },
                NOW,
            )
            .unwrap();
        let lease = leases
            .issue(&scope, &permit, u64::from(CHUNK_SIZE) + 1, NOW)
            .unwrap();

        assert!(matches!(
            authorize_bulk_request(
                &scope,
                &leases,
                &peer(),
                &request(BulkOperation::Chunk, content, lease.lease_id, 2),
                &manifest,
                NOW,
            ),
            Err(asl_types::error::AslError::NotFound)
        ));
        assert!(matches!(
            authorize_bulk_request(
                &scope,
                &leases,
                &peer(),
                &request(BulkOperation::Inline, content, lease.lease_id, 0),
                &manifest,
                NOW,
            ),
            Err(asl_types::error::AslError::NotFound)
        ));
    }
}
