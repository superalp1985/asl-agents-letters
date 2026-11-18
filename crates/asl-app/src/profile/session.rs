use asl_types::{
    error::AslError,
    ids::{AgentId, PeerId},
    protocol::Hello,
    record::RecordPayload,
};

use crate::chain::{IdentityResolver, RegistryStateV1};
use asl_net::transport::{AuthenticatedPeer, LocalConnectionId};

use super::{RecordHistory, resolve_active, verify_record};

enum State {
    AwaitingHello,
    Admitted {
        agent: AgentId,
        registry: RegistryStateV1,
        directory_hash: blake3::Hash,
        expires_at_ms: u64,
        last_checked_ms: u64,
    },
    Closed,
}

/// One Core gate per authenticated transport connection. Never construct it
/// using a PeerId claimed in a remote payload.
pub struct DeviceSession {
    peer: PeerId,
    transport: Option<AuthenticatedPeer>,
    state: State,
}

impl DeviceSession {
    pub fn from_transport(connection: AuthenticatedPeer) -> Self {
        Self {
            peer: connection.peer_id().clone(),
            transport: Some(connection),
            state: State::AwaitingHello,
        }
    }

    pub fn connection_id(&self) -> Option<LocalConnectionId> {
        self.transport
            .as_ref()
            .map(AuthenticatedPeer::connection_id)
    }

    #[cfg(test)]
    pub(crate) fn from_test_peer(peer: asl_types::ids::PeerId) -> Self {
        Self {
            peer,
            transport: None,
            state: State::AwaitingHello,
        }
    }

    fn require_live(&self) -> Result<(), AslError> {
        match &self.transport {
            Some(connection) if connection.is_live() => Ok(()),
            #[cfg(test)]
            None => Ok(()),
            _ => Err(AslError::InvalidIdentity),
        }
    }

    pub fn accept_hello(
        &mut self,
        hello: &Hello,
        signed_directory: &[u8],
        history: &mut RecordHistory,
        resolver: &mut dyn IdentityResolver,
        now_ms: u64,
    ) -> Result<(), AslError> {
        // Failed or repeated hellos consume this connection's admission attempt.
        if !matches!(
            std::mem::replace(&mut self.state, State::Closed),
            State::AwaitingHello
        ) {
            return Err(AslError::InvalidMessage);
        }
        self.require_live()?;
        if hello.major != 1 {
            return Err(AslError::IncompatibleVersion);
        }
        let certificate = &hello.device_certificate;
        if hello.peer_id != self.peer
            || certificate.peer_id != self.peer
            || certificate.agent_id != hello.agent_id
        {
            return Err(AslError::InvalidDeviceCertificate);
        }
        let verified = verify_record(signed_directory, hello.agent_id, now_ms, resolver)?;
        let record = &verified.signed().record;
        let RecordPayload::DeviceDirectory(directory) = &record.payload else {
            return Err(AslError::InvalidDeviceCertificate);
        };
        // verify_record already validates the signature and validity interval of
        // every directory certificate; require the exact validated certificate.
        if !directory.devices.contains(certificate) {
            return Err(AslError::InvalidDeviceCertificate);
        }
        self.require_live()?;
        history.observe(&verified)?;
        self.state = State::Admitted {
            agent: hello.agent_id,
            registry: verified.registry_state,
            directory_hash: blake3::hash(verified.bytes()),
            expires_at_ms: record.expires_at_ms.min(certificate.expires_at_ms),
            last_checked_ms: now_ms,
        };
        Ok(())
    }

    /// Recheck before admitting business traffic. A newer directory or an
    /// unavailable identity closes the gate; reconnecting requires a new hello.
    pub fn current_agent(
        &mut self,
        history: &RecordHistory,
        resolver: &mut dyn IdentityResolver,
        now_ms: u64,
    ) -> Result<AgentId, AslError> {
        if matches!(self.state, State::AwaitingHello) {
            return Err(AslError::InvalidIdentity);
        }
        let State::Admitted {
            agent,
            registry,
            directory_hash,
            expires_at_ms,
            last_checked_ms,
        } = std::mem::replace(&mut self.state, State::Closed)
        else {
            return Err(AslError::InvalidIdentity);
        };
        self.require_live()?;
        if now_ms < last_checked_ms || now_ms >= expires_at_ms {
            return Err(AslError::ExpiredMessage);
        }
        if !history.matches_directory(agent, directory_hash)
            || resolve_active(agent, now_ms, resolver)? != registry
        {
            return Err(AslError::InvalidIdentity);
        }
        self.require_live()?;
        self.state = State::Admitted {
            agent,
            registry,
            directory_hash,
            expires_at_ms,
            last_checked_ms: now_ms,
        };
        Ok(agent)
    }

    pub fn close(&mut self) {
        self.state = State::Closed;
    }
}
