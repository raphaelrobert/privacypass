//! Response implementation of the Privately Verifiable Token protocol.

use hybrid_array::Array;
use log::warn;
use tls_codec::{Deserialize, Serialize, Size};
use typenum::Unsigned;
use voprf::*;

use crate::{
    auth::authorize::Token,
    common::{
        errors::{IssueTokenError, SerializationError},
        private::PrivateCipherSuite,
    },
};

use super::{PrivateToken, request::TokenState};

/// Token response as specified in the spec:
///
/// ```c
/// struct {
///     uint8_t evaluate_msg[Ne];
///     uint8_t evaluate_proof[Ns+Ns];
///  } TokenResponse;
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct TokenResponse<CS: PrivateCipherSuite> {
    pub(crate) evaluate_msg: Array<u8, EvaluationElementLen<CS>>,
    pub(crate) evaluate_proof: Array<u8, ProofLen<CS>>,
}

impl<CS: PrivateCipherSuite> TokenResponse<CS> {
    /// Create a new `TokenResponse` from a byte slice.
    ///
    /// # Errors
    /// Returns `SerializationError::InvalidData` if the byte slice is not valid.
    pub fn try_from_bytes(mut bytes: &[u8]) -> Result<Self, SerializationError> {
        Self::tls_deserialize(&mut bytes)
            .map_err(|source| SerializationError::InvalidData { source })
    }

    #[cfg(feature = "kat")]
    /// Returns the evaluated message
    #[must_use]
    pub fn evaluate_msg(&self) -> &[u8] {
        &self.evaluate_msg
    }
}

impl<CS: PrivateCipherSuite> Size for TokenResponse<CS> {
    fn tls_serialized_len(&self) -> usize {
        EvaluationElementLen::<CS>::USIZE + ProofLen::<CS>::USIZE
    }
}

impl<CS: PrivateCipherSuite> Serialize for TokenResponse<CS> {
    fn tls_serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::result::Result<usize, tls_codec::Error> {
        writer.write_all(&self.evaluate_msg)?;
        writer.write_all(&self.evaluate_proof)?;
        Ok(self.evaluate_msg.len() + self.evaluate_proof.len())
    }
}

impl<CS: PrivateCipherSuite> Deserialize for TokenResponse<CS> {
    fn tls_deserialize<R: std::io::Read>(
        bytes: &mut R,
    ) -> std::result::Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let mut evaluate_msg = Array::default();
        bytes.read_exact(&mut evaluate_msg)?;
        let mut evaluate_proof = Array::default();
        bytes.read_exact(&mut evaluate_proof)?;
        Ok(TokenResponse {
            evaluate_msg,
            evaluate_proof,
        })
    }
}

impl<CS: PrivateCipherSuite> TokenResponse<CS> {
    /// Issue a token.
    ///
    /// # Errors
    /// Returns an error if the response is invalid.
    pub fn issue_token(
        self,
        token_state: &TokenState<CS>,
    ) -> Result<PrivateToken<CS>, IssueTokenError> {
        let token_type = token_state.token_input.token_type;
        let evaluation_element = EvaluationElement::deserialize(&self.evaluate_msg)
            .inspect_err(|e| warn!(error:% = e; "Failed to deserialize evaluation element"))
            .map_err(|source| IssueTokenError::InvalidEvaluationElement { token_type, source })?;
        let proof = Proof::deserialize(&self.evaluate_proof)
            .inspect_err(|e| warn!(error:% = e; "Failed to deserialize proof"))
            .map_err(|source| IssueTokenError::InvalidProof { token_type, source })?;
        let token_input = token_state.token_input.serialize();
        // authenticator = client_context.Finalize(token_input, blind, evaluated_element, blinded_element, proof)
        let authenticator = token_state
            .client
            .finalize(
                &token_input,
                &evaluation_element,
                &proof,
                token_state.public_key,
            )
            .inspect_err(|e| warn!(error:% = e; "Failed to finalize token"))
            .map_err(|source| IssueTokenError::FinalizationFailed { token_type, source })?;

        Ok(Token::new(
            CS::token_type(),
            token_state.token_input.nonce,
            token_state.challenge_digest,
            token_state.token_input.token_key_id,
            authenticator,
        ))
    }
}
