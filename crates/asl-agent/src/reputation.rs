use std::collections::{HashMap, HashSet};

use asl_store::evidence::{ContactEvidence, TrustCounts};
use asl_types::ids::AgentId;

/// Soft ordering only: candidates are drawn exclusively from the caller's
/// already-authorized list.
pub fn rank_authorized_contacts(
    authorized: &[AgentId],
    preferred: &[AgentId],
    evidence: &[ContactEvidence],
) -> Vec<AgentId> {
    let preferred = preferred.iter().copied().collect::<HashSet<_>>();
    let evidence = evidence
        .iter()
        .map(|entry| (entry.agent_id, score(entry)))
        .collect::<HashMap<_, _>>();
    let mut ranked = Vec::with_capacity(authorized.len());
    let mut seen = HashSet::new();
    for (index, agent_id) in authorized.iter().copied().enumerate() {
        if seen.insert(agent_id) {
            ranked.push((
                index,
                agent_id,
                preferred.contains(&agent_id),
                evidence.get(&agent_id).copied().unwrap_or_default(),
            ));
        }
    }
    ranked.sort_by(|left, right| {
        right
            .2
            .cmp(&left.2)
            .then_with(|| right.3.cmp(&left.3))
            .then_with(|| left.0.cmp(&right.0))
    });
    ranked
        .into_iter()
        .map(|(_, agent_id, _, _)| agent_id)
        .collect()
}

fn score(evidence: &ContactEvidence) -> i32 {
    balance(evidence.integrity) * 4
        + balance(evidence.evidence) * 2
        + balance(evidence.promise) * 2
        + balance(evidence.availability)
        + evidence.contributions.min(20) as i32
}

fn balance(counts: TrustCounts) -> i32 {
    (i64::from(counts.positive) - i64::from(counts.negative)).clamp(-5, 5) as i32
}
