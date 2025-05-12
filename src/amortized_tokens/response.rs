//! Response implementation of the Amortized Tokens protocol.

use tls_codec::{Deserialize, Serialize, Size};
use typenum::Unsigned;
use voprf::{EvaluationElement, Group, Proof, Result, VoprfClient};

use crate::{
    PPCipherSuite,
    auth::authorize::Token,
    common::errors::{IssueTokenError, SerializationError},
};

use super::{AmortizedToken, TokenState};

/// Evaluated element as specified in the spec:
///
/// ```c
/// struct {
///     uint8_t evaluated_element[Ne];
/// } EvaluatedElement;
/// ```

#[derive(Debug, PartialEq)]
pub struct EvaluatedElement<CS: PPCipherSuite> {
    pub(crate) _marker: std::marker::PhantomData<CS>,
    pub(crate) evaluated_element: Vec<u8>,
}

/// Token response as specified in the spec:
///
/// ```c
/// struct {
///     EvaluatedElement evaluated_elements[Nr];
///     uint8_t evaluated_proof[Ns + Ns];
///  } TokenResponse;
/// ```
#[derive(Debug)]
pub struct TokenResponse<CS: PPCipherSuite> {
    pub(crate) _marker: std::marker::PhantomData<CS>,
    pub(crate) evaluated_elements: Vec<EvaluatedElement<CS>>,
    pub(crate) evaluated_proof: Vec<u8>,
}

impl<CS: PPCipherSuite> TokenResponse<CS> {
    /// Create a new `TokenResponse` from a byte slice.
    ///
    /// # Errors
    /// Returns `SerializationError::InvalidData` if the byte slice is not a
    /// valid `TokenResponse`.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        let mut bytes = bytes;
        Self::tls_deserialize(&mut bytes).map_err(|_| SerializationError::InvalidData)
    }

    /// Issue a token.
    ///
    /// # Errors
    /// Returns an error if the token response is invalid.
    pub fn issue_tokens(
        self,
        token_state: &TokenState<CS>,
    ) -> Result<Vec<AmortizedToken<CS>>, IssueTokenError> {
        let mut evaluated_elements = Vec::new();
        for element in self.evaluated_elements.iter() {
            let evaluated_element =
                EvaluationElement::<CS>::deserialize(&element.evaluated_element)
                    .map_err(|_| IssueTokenError::InvalidTokenResponse)?;
            evaluated_elements.push(evaluated_element);
        }

        let proof = Proof::deserialize(&self.evaluated_proof)
            .map_err(|_| IssueTokenError::InvalidTokenResponse)?;

        let client_batch_finalize_result = VoprfClient::batch_finalize(
            &token_state
                .token_inputs
                .iter()
                .map(|token_input| token_input.serialize())
                .collect::<Vec<_>>(),
            &token_state.clients.to_vec(),
            &evaluated_elements,
            &proof,
            token_state.public_key,
        )
        .map_err(|_| IssueTokenError::InvalidTokenResponse)?
        .collect::<Result<Vec<_>>>()
        .map_err(|_| IssueTokenError::InvalidTokenResponse)?;

        let mut tokens = Vec::new();

        for (authenticator, token_input) in client_batch_finalize_result
            .iter()
            .zip(token_state.token_inputs.iter())
        {
            let token = Token::new(
                token_input.token_type,
                token_input.nonce,
                token_state.challenge_digest,
                token_input.token_key_id,
                authenticator.to_owned(),
            );
            tokens.push(token);
        }

        Ok(tokens)
    }

    #[cfg(feature = "kat")]
    /// Returns the evaluated elements
    #[must_use]
    pub fn evaluated_elements(&self) -> &[EvaluatedElement<CS>] {
        &self.evaluated_elements
    }
}

impl<CS: PPCipherSuite> Size for EvaluatedElement<CS> {
    fn tls_serialized_len(&self) -> usize {
        <<CS::Group as Group>::ElemLen as Unsigned>::USIZE
    }
}

impl<CS: PPCipherSuite> Serialize for EvaluatedElement<CS> {
    fn tls_serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::result::Result<usize, tls_codec::Error> {
        writer.write_all(&self.evaluated_element)?;
        Ok(self.evaluated_element.len())
    }
}

impl<CS: PPCipherSuite> Deserialize for EvaluatedElement<CS> {
    fn tls_deserialize<R: std::io::Read>(
        bytes: &mut R,
    ) -> std::result::Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let mut evaluated_element = vec![0u8; <<CS::Group as Group>::ElemLen as Unsigned>::USIZE];
        bytes.read_exact(&mut evaluated_element)?;
        Ok(EvaluatedElement {
            _marker: std::marker::PhantomData,
            evaluated_element,
        })
    }
}

impl<CS: PPCipherSuite> Size for TokenResponse<CS> {
    fn tls_serialized_len(&self) -> usize {
        let len = 2 * <<CS::Group as Group>::ScalarLen as Unsigned>::USIZE;
        self.evaluated_elements.tls_serialized_len() + len
    }
}

impl<CS: PPCipherSuite> Deserialize for TokenResponse<CS> {
    fn tls_deserialize<R: std::io::Read>(
        bytes: &mut R,
    ) -> std::result::Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let evaluated_elements = Vec::<EvaluatedElement<CS>>::tls_deserialize(bytes)?;
        let len = 2 * <<CS::Group as Group>::ScalarLen as Unsigned>::USIZE;
        // read len bytes
        let mut evaluated_proof = vec![0u8; len];
        bytes.read_exact(&mut evaluated_proof)?;
        Ok(TokenResponse {
            _marker: std::marker::PhantomData,
            evaluated_elements,
            evaluated_proof,
        })
    }
}

impl<CS: PPCipherSuite> Serialize for TokenResponse<CS> {
    fn tls_serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::result::Result<usize, tls_codec::Error> {
        let written = self.evaluated_elements.tls_serialize(writer)?;
        writer.write_all(&self.evaluated_proof)?;
        Ok(written + self.evaluated_proof.len())
    }
}
