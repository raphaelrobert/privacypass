//! Response implementation of the Privately Verifiable Token protocol.

use tls_codec::{Deserialize, Serialize, Size};
use typenum::Unsigned;
use voprf::*;

use crate::{
    auth::authorize::Token,
    common::{
        errors::{IssueTokenError, SerializationError},
        private::PPCipherSuite,
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
pub struct TokenResponse<CS: PPCipherSuite> {
    pub(crate) _marker: std::marker::PhantomData<CS>,
    pub(crate) evaluate_msg: Vec<u8>,
    pub(crate) evaluate_proof: Vec<u8>,
}

impl<CS: PPCipherSuite> TokenResponse<CS> {
    /// Create a new `TokenResponse` from a byte slice.
    ///
    /// # Errors
    /// Returns `SerializationError::InvalidData` if the byte slice is not valid.
    pub fn try_from_bytes(mut bytes: &[u8]) -> Result<Self, SerializationError> {
        Self::tls_deserialize(&mut bytes).map_err(|_| SerializationError::InvalidData)
    }

    #[cfg(feature = "kat")]
    /// Returns the evaluated message
    #[must_use]
    pub fn evaluate_msg(&self) -> &[u8] {
        &self.evaluate_msg
    }
}

impl<CS: PPCipherSuite> Size for TokenResponse<CS> {
    fn tls_serialized_len(&self) -> usize {
        let len = <<CS::Group as Group>::ElemLen as Unsigned>::USIZE;
        let proof_len = <<CS::Group as Group>::ScalarLen as Unsigned>::USIZE;
        len + 2 * proof_len
    }
}

impl<CS: PPCipherSuite> Serialize for TokenResponse<CS> {
    fn tls_serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::result::Result<usize, tls_codec::Error> {
        writer.write_all(&self.evaluate_msg)?;
        writer.write_all(&self.evaluate_proof)?;
        Ok(self.evaluate_msg.len() + self.evaluate_proof.len())
    }
}

impl<CS: PPCipherSuite> Deserialize for TokenResponse<CS> {
    fn tls_deserialize<R: std::io::Read>(
        bytes: &mut R,
    ) -> std::result::Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let mut evaluate_msg = vec![0u8; <<CS::Group as Group>::ElemLen as Unsigned>::USIZE];
        bytes.read_exact(&mut evaluate_msg)?;
        let mut evaluate_proof =
            vec![0u8; 2 * <<CS::Group as Group>::ScalarLen as Unsigned>::USIZE];
        bytes.read_exact(&mut evaluate_proof)?;
        Ok(TokenResponse {
            _marker: std::marker::PhantomData,
            evaluate_msg,
            evaluate_proof,
        })
    }
}

impl<CS: PPCipherSuite> TokenResponse<CS> {
    /// Issue a token.
    ///
    /// # Errors
    /// Returns an error if the response is invalid.
    pub fn issue_token(
        self,
        token_state: &TokenState<CS>,
    ) -> Result<PrivateToken<CS>, IssueTokenError> {
        let evaluation_element = EvaluationElement::deserialize(&self.evaluate_msg)
            .map_err(|_| IssueTokenError::InvalidTokenResponse)?;
        let proof = Proof::deserialize(&self.evaluate_proof)
            .map_err(|_| IssueTokenError::InvalidTokenResponse)?;
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
            .map_err(|_| IssueTokenError::InvalidTokenResponse)?;

        Ok(Token::new(
            CS::token_type(),
            token_state.token_input.nonce,
            token_state.challenge_digest,
            token_state.token_input.token_key_id,
            authenticator,
        ))
    }
}
