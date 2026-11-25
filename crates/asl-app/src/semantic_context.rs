mod evaluator;

pub use evaluator::{
    ConformanceReadySemanticContextBundle, Rational, SemanticConcept, SemanticEvaluation,
    SemanticValue, check_context_conformance, evaluate_semantic_expression,
};

use asl_types::{
    error::AslError,
    ids::AgentId,
    protocol::{SemanticContextBundle, SemanticContextRef, SignedSemanticContextBundle},
};

use crate::identity::{AgentIdentity, verify_root_signature};

/// A structurally valid package whose root signature matches the supplied
/// owner and the controller from a caller-verified active chain state.
///
/// This does not mean its definitions have passed conformance evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedSemanticContextBundle {
    bundle: SemanticContextBundle,
    context_ref: SemanticContextRef,
    signature: asl_types::ids::Signature65,
}

impl AuthenticatedSemanticContextBundle {
    pub fn bundle(&self) -> &SemanticContextBundle {
        &self.bundle
    }

    pub fn context_ref(&self) -> SemanticContextRef {
        self.context_ref
    }

    pub fn signed_bundle(&self) -> SignedSemanticContextBundle {
        SignedSemanticContextBundle {
            bundle: self.bundle.clone(),
            signature: self.signature,
        }
    }
}

pub fn sign_semantic_context(
    identity: &AgentIdentity,
    bundle: SemanticContextBundle,
) -> Result<SignedSemanticContextBundle, AslError> {
    if bundle.authority != identity.agent_id() {
        return Err(AslError::InvalidIdentity);
    }
    let signature = identity.sign_domain_message(&bundle.signing_bytes()?)?;
    Ok(SignedSemanticContextBundle { bundle, signature })
}

/// `expected_controller` must come from an identity state verified against
/// the caller's current finalized chain checkpoint.
pub fn authenticate_semantic_context(
    signed: SignedSemanticContextBundle,
    expected_agent: AgentId,
    expected_controller: [u8; 20],
) -> Result<AuthenticatedSemanticContextBundle, AslError> {
    if signed.bundle.authority != expected_agent {
        return Err(AslError::InvalidIdentity);
    }
    let message = signed.bundle.signing_bytes()?;
    verify_root_signature(&message, signed.signature, expected_controller)?;
    let context_ref = signed.bundle.context_ref()?;
    Ok(AuthenticatedSemanticContextBundle {
        bundle: signed.bundle,
        context_ref,
        signature: signed.signature,
    })
}
