//! Selects bounded local evidence for an autonomous group reply.
//!
//! The incoming query is search text only. This module never treats it as a
//! path, URL, action, tool request, or policy input.

use std::{
    collections::{HashMap, HashSet},
    time::{SystemTime, UNIX_EPOCH},
};

use asl_agent::{
    ActReplyEvidence,
    act_reply::{MAX_ACT_REPLY_EVIDENCE, MAX_ACT_REPLY_EVIDENCE_CHARS},
};
use asl_policy::{
    AccessOperation, AccessRequest, PolicyEngine, PolicyService, Principal, ProviderPolicy,
    ScopedPolicy,
};
use asl_store::{Store, search::group::GroupRequester};
use asl_types::{
    error::AslError,
    ids::PeerId,
    protocol::MAX_ACT_NL_BYTES,
    task::{GrantId, GroupId, ProviderId, ResourceKey},
};

use crate::libraries::LocalLibraries;

// Keep the follow-up model call on the same permits. PolicyEngine itself caps
// permit lifetimes at 60 seconds.
const PERMIT_LIFETIME_MS: u64 = 60_000;
const MAX_EVIDENCE_BYTES: u64 = (MAX_ACT_REPLY_EVIDENCE_CHARS * 4) as u64;
const SEARCH_LIMIT: u32 = (MAX_ACT_REPLY_EVIDENCE * 4) as u32;
const MAX_QUERY_BYTES: usize = 4_096;

/// Explicit handoff from the Core thread to the model-reply worker.
///
/// The policy engine owns the exact group snapshot used to issue the permits.
/// The worker obtains fresh read and model scopes from it and passes both to
/// `generate_act_reply`, which revalidates every permit before and after the
/// model call.
pub(crate) struct AutoReplyEvidenceContext {
    pub(crate) provider: ProviderId,
    pub(crate) evidence: Vec<ActReplyEvidence>,
    pub(crate) policy: PolicyEngine,
    pub(crate) peer: PeerId,
    pub(crate) group: GroupId,
}

impl AutoReplyEvidenceContext {
    pub(crate) fn policies(&self) -> (ScopedPolicy<'_>, ScopedPolicy<'_>) {
        (
            self.policy.for_group(self.peer.clone(), self.group.clone()),
            self.policy.for_group(self.peer.clone(), self.group.clone()),
        )
    }
}

/// Selects at most four resources that carry both group-scoped `ReadChunk`
/// and `ModelInput` authority for the selected provider.
///
/// Empty, NUL-containing, UTF-8-oversized, and search-oversized text returns
/// a context with no evidence. Individual stale or non-text candidates are
/// skipped after the initial bounded search.
pub(crate) fn select_auto_reply_evidence(
    store: &Store,
    libraries: &LocalLibraries,
    requester: &GroupRequester,
    provider: ProviderId,
    provider_local: bool,
    untrusted_nl_body: &str,
) -> Result<AutoReplyEvidenceContext, AslError> {
    let (mut snapshot, keys) = store.group_search_snapshot(requester)?;

    // Store can prove that the selected provider has a user approval record,
    // but provider locality belongs to the endpoint registry. Mark it remote
    // here so LocalOnly grants fail closed. The gateway performs the complete
    // endpoint fingerprint check before any request leaves the process.
    let provider_authorized = store.model_provider_approval(&provider.0)?.is_some();
    snapshot.providers.insert(
        provider.clone(),
        ProviderPolicy {
            authorized: provider_authorized,
            local: provider_local,
        },
    );

    let grants = snapshot
        .resources
        .iter()
        .map(|(key, resource)| (key.clone(), resource.grant_id.clone()))
        .collect::<HashMap<ResourceKey, GrantId>>();
    let policy = PolicyEngine::new(snapshot, PERMIT_LIFETIME_MS)?;
    let mut context = AutoReplyEvidenceContext {
        provider,
        evidence: Vec::new(),
        policy,
        peer: requester.direct.peer.clone(),
        group: requester.group_id.clone(),
    };

    if !query_is_bounded(untrusted_nl_body) || keys.is_empty() {
        return Ok(context);
    }

    let search_result = {
        let search_policy = context
            .policy
            .for_group(context.peer.clone(), context.group.clone());
        store
            .peer_search(&search_policy, requester.direct.agent)
            .search_local_text(&keys, untrusted_nl_body, SEARCH_LIMIT)
    };
    let hits = match search_result {
        Ok(hits) => hits,
        Err(AslError::InvalidMessage) => return Ok(context),
        Err(error) => return Err(error),
    };
    let (read_policy, model_policy) = context.policies();
    let mut seen = HashSet::with_capacity(hits.len());
    let mut evidence = Vec::with_capacity(MAX_ACT_REPLY_EVIDENCE);

    for hit in hits {
        if evidence.len() == MAX_ACT_REPLY_EVIDENCE {
            break;
        }
        if !seen.insert(hit.content_id) {
            continue;
        }
        let Some(grant_id) = grants.get(&hit.resource_key).cloned() else {
            continue;
        };
        let read_request = AccessRequest {
            grant_id: grant_id.clone(),
            resource_key: hit.resource_key.clone(),
            principal: Principal::Agent(requester.direct.agent),
            operation: AccessOperation::ReadChunk,
        };
        let model_request = AccessRequest {
            grant_id,
            resource_key: hit.resource_key,
            principal: Principal::ModelProvider(context.provider.clone()),
            operation: AccessOperation::ModelInput,
        };
        let issued_at_ms = now_ms()?;
        let Ok(read) = read_policy.authorize(&read_request, issued_at_ms) else {
            continue;
        };
        let Ok(model) = model_policy.authorize(&model_request, issued_at_ms) else {
            continue;
        };

        let mut snapshot = match libraries.open_snapshot(hit.content_id) {
            Ok(snapshot) => snapshot,
            Err(AslError::NotFound | AslError::InvalidDatabase) => continue,
            Err(error) => return Err(error),
        };
        let length = snapshot.manifest().file_size.min(MAX_EVIDENCE_BYTES);
        let Ok(length) = u32::try_from(length) else {
            continue;
        };
        let bytes = match snapshot.read_range(0, length) {
            Ok(bytes) => bytes,
            Err(AslError::NotFound | AslError::InvalidDatabase) => continue,
            Err(error) => return Err(error),
        };
        let Some(excerpt) = bounded_utf8_excerpt(&bytes) else {
            continue;
        };

        let revalidated_at_ms = now_ms()?;
        if read_policy.revalidate(&read, revalidated_at_ms).is_err()
            || model_policy.revalidate(&model, revalidated_at_ms).is_err()
        {
            continue;
        }
        let Ok(candidate) = ActReplyEvidence::new(excerpt, read, model) else {
            continue;
        };
        evidence.push(candidate);
    }

    context.evidence = evidence;
    Ok(context)
}

fn query_is_bounded(text: &str) -> bool {
    !text.trim().is_empty()
        && text.len() <= MAX_ACT_NL_BYTES.min(MAX_QUERY_BYTES)
        && !text.as_bytes().contains(&0)
}

fn bounded_utf8_excerpt(bytes: &[u8]) -> Option<String> {
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(error) => std::str::from_utf8(&bytes[..error.valid_up_to()]).ok()?,
    };
    if text.as_bytes().contains(&0) {
        return None;
    }
    let excerpt = text
        .chars()
        .take(MAX_ACT_REPLY_EVIDENCE_CHARS)
        .collect::<String>();
    let excerpt = excerpt.trim();
    (!excerpt.is_empty()).then(|| excerpt.to_owned())
}

fn now_ms() -> Result<u64, AslError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AslError::InvalidPolicyState)?
        .as_millis();
    u64::try_from(millis).map_err(|_| AslError::InvalidPolicyState)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_is_sendable() {
        fn assert_send<T: Send>() {}
        assert_send::<AutoReplyEvidenceContext>();
    }

    #[test]
    fn query_is_text_only_and_bounded() {
        assert!(query_is_bounded("rust sqlite"));
        assert!(!query_is_bounded(""));
        assert!(!query_is_bounded(" \n\t "));
        assert!(!query_is_bounded("rust\0sqlite"));
        assert!(!query_is_bounded(&"a".repeat(MAX_QUERY_BYTES + 1)));
    }

    #[test]
    fn excerpt_is_valid_utf8_and_character_bounded() {
        let text = "界".repeat(MAX_ACT_REPLY_EVIDENCE_CHARS + 20);
        let excerpt = bounded_utf8_excerpt(text.as_bytes()).unwrap();
        assert_eq!(excerpt.chars().count(), MAX_ACT_REPLY_EVIDENCE_CHARS);

        let invalid_tail = [b'o', b'k', 0xe7, 0x95];
        assert_eq!(bounded_utf8_excerpt(&invalid_tail).as_deref(), Some("ok"));
        assert_eq!(bounded_utf8_excerpt(b" \n\t "), None);
        assert_eq!(bounded_utf8_excerpt(b"a\0b"), None);
    }
}
