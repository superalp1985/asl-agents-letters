use std::collections::HashMap;

use asl_types::ids::AgentId;

use super::{
    ChainError, EthereumLightClient, EthereumProofVerifier, IdentityProofV1, IdentityProofVerifier,
    IdentityResolution, LimitedReason, RegistryStatus, VerifiedIdentity, config::INTERFACE_VERSION,
};

pub trait IdentityResolver {
    fn interface_version(&self) -> u16;

    fn resolve(&mut self, agent: AgentId, now_secs: u64) -> IdentityResolution;
}

struct CachedIdentity {
    identity: VerifiedIdentity,
    last_used_secs: u64,
}

pub struct EthereumIdentityResolver {
    light_client: EthereumLightClient,
    verifier: EthereumProofVerifier,
    cache: HashMap<AgentId, CachedIdentity>,
    max_cache_age_secs: u64,
    capacity: usize,
}

impl EthereumIdentityResolver {
    pub fn new(
        light_client: EthereumLightClient,
        verifier: EthereumProofVerifier,
        max_cache_age_secs: u64,
        capacity: usize,
    ) -> Result<Self, ChainError> {
        if light_client.chain_id() != verifier.deployment().chain_id
            || max_cache_age_secs == 0
            || max_cache_age_secs > light_client.max_finality_age_secs()
            || !(1..=128).contains(&capacity)
        {
            return Err(ChainError::InvalidConfiguration);
        }
        Ok(Self {
            light_client,
            verifier,
            cache: HashMap::new(),
            max_cache_age_secs,
            capacity,
        })
    }

    pub fn light_client(&self) -> &EthereumLightClient {
        &self.light_client
    }

    pub fn light_client_mut(&mut self) -> &mut EthereumLightClient {
        &mut self.light_client
    }

    pub fn accept_proof(
        &mut self,
        expected_agent: AgentId,
        proof: &IdentityProofV1,
        now_secs: u64,
    ) -> Result<(), ChainError> {
        let finalized = self.light_client.finalized(now_secs)?;
        let identity = self.verifier.verify(&finalized, expected_agent, proof)?;
        if now_secs
            .checked_sub(identity.finalized.timestamp_secs)
            .ok_or(ChainError::ClockBeforeState)?
            > self.max_cache_age_secs
        {
            return Err(ChainError::StaleFinality);
        }
        self.cache_verified(identity, now_secs)
    }

    fn cache_verified(
        &mut self,
        identity: VerifiedIdentity,
        now_secs: u64,
    ) -> Result<(), ChainError> {
        if let Some(previous) = self.cache.get(&identity.agent_id) {
            let previous = &previous.identity;
            if identity.finalized.block_number < previous.finalized.block_number
                || identity.state.sequence < previous.state.sequence
                || (identity.state.sequence == previous.state.sequence
                    && identity.state != previous.state)
                || (previous.state.status == RegistryStatus::Revoked
                    && identity.state.status != RegistryStatus::Revoked)
                || (identity.finalized.block_number == previous.finalized.block_number
                    && (identity.finalized.block_hash != previous.finalized.block_hash
                        || identity.finalized.state_root != previous.finalized.state_root))
            {
                return Err(ChainError::Rollback);
            }
        }
        self.cache.retain(|_, cached| {
            now_secs
                .checked_sub(cached.identity.finalized.timestamp_secs)
                .is_some_and(|age| age <= self.max_cache_age_secs)
        });
        if !self.cache.contains_key(&identity.agent_id) && self.cache.len() >= self.capacity {
            let oldest = self
                .cache
                .iter()
                .min_by_key(|(agent, cached)| (cached.last_used_secs, agent.0))
                .map(|(agent, _)| *agent)
                .ok_or(ChainError::CacheFull)?;
            self.cache.remove(&oldest);
        }
        self.cache.insert(
            identity.agent_id,
            CachedIdentity {
                identity,
                last_used_secs: now_secs,
            },
        );
        Ok(())
    }
}

#[cfg(test)]
#[path = "resolver_tests.rs"]
mod tests;

impl IdentityResolver for EthereumIdentityResolver {
    fn interface_version(&self) -> u16 {
        INTERFACE_VERSION
    }

    fn resolve(&mut self, agent: AgentId, now_secs: u64) -> IdentityResolution {
        let Some(cached) = self.cache.get_mut(&agent) else {
            return IdentityResolution::Limited(LimitedReason::Unknown);
        };
        let identity = &cached.identity;
        cached.last_used_secs = now_secs;
        if identity.state.status == RegistryStatus::Revoked {
            return IdentityResolution::Limited(LimitedReason::Revoked);
        }
        if self.light_client.finalized(now_secs).is_err() {
            return IdentityResolution::Limited(LimitedReason::ChainUnavailable);
        }
        if now_secs
            .checked_sub(identity.finalized.timestamp_secs)
            .is_none_or(|age| age > self.max_cache_age_secs)
        {
            return IdentityResolution::Limited(LimitedReason::StaleProof);
        }
        if identity.state.status == RegistryStatus::Unregistered {
            return IdentityResolution::Limited(LimitedReason::Unregistered);
        }
        IdentityResolution::Verified(Box::new(identity.clone()))
    }
}
