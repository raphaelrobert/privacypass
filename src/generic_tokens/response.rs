//! Response implementation of the Generic Token protocol.

use p384::NistP384;
use tls_codec::Deserialize;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
use voprf::Ristretto255;

use crate::{
    TokenType,
    common::errors::{IssueTokenError, SerializationError},
};

use super::{GenericToken, GenericTokenState, TokenStates};

/// Generic TokenResponse as specified in the spec:
///
/// ```c
/// struct {
///     optional TokenResponse token_responses<V>;
///   } BatchTokenRequest
/// ```
#[repr(u16)]
#[derive(Debug, Clone, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub enum GenericTokenResponse {
    /// Type VOPRF(P-384, SHA-384), RFC 9578
    #[tls_codec(discriminant = "TokenType::PrivateP384")]
    PrivateP384(Box<crate::private_tokens::TokenResponse<NistP384>>),
    /// Type Blind RSA (2048-bit), RFC 9578
    #[tls_codec(discriminant = "TokenType::Public")]
    Public(Box<crate::public_tokens::TokenResponse>),
    /// Type VOPRF(Ristretto255, SHA-512), RFC XXXX
    #[tls_codec(discriminant = "TokenType::PrivateRistretto255")]
    PrivateRistretto255(Box<crate::private_tokens::TokenResponse<Ristretto255>>),
}

/// Token response as specified in the spec:
///
/// ```c
/// struct {
///     TokenResponse token_response<V>; /* Defined by token_type */
///   } OptionalTokenResponse;
///```
#[derive(Debug, Clone, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct OptionalTokenResponse {
    /// Optional token response
    pub token_response: Option<GenericTokenResponse>,
}

/// Token response as specified in the spec:
///
/// ```c
///   struct {
///     OptionalTokenResponse token_responses<0..2^16-1>;
///   } BatchTokenResponse
/// ```
#[derive(Debug, Clone, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct BatchTokenResponse {
    /// Token responses
    pub token_responses: Vec<OptionalTokenResponse>,
}

impl BatchTokenResponse {
    /// Create a new `BatchTokenResponse` from a byte slice.
    ///
    /// # Errors
    /// Returns `SerializationError::InvalidData` if the byte slice is not valid.
    pub fn try_from_bytes(mut bytes: &[u8]) -> Result<Self, SerializationError> {
        Self::tls_deserialize(&mut bytes).map_err(|_| SerializationError::InvalidData)
    }
}

impl BatchTokenResponse {
    /// Issues tokens.
    ///
    /// # Errors
    /// Returns an error if the response is invalid.
    pub fn issue_tokens(
        self,
        token_states: &TokenStates,
    ) -> Result<Vec<GenericToken>, IssueTokenError> {
        let mut tokens = Vec::new();

        for (token_response, token_state) in self
            .token_responses
            .into_iter()
            .map(|r| r.token_response)
            .zip(token_states.token_states.iter())
        {
            if let Some(response) = token_response {
                match (response, token_state) {
                    (
                        GenericTokenResponse::PrivateP384(response),
                        GenericTokenState::PrivateP384(state),
                    ) => {
                        let token = response
                            .issue_token(state)
                            .map(GenericToken::from_private_p384)?;
                        tokens.push(token);
                    }
                    (GenericTokenResponse::Public(response), GenericTokenState::Public(state)) => {
                        let token = response.issue_token(state).map(GenericToken::from_public)?;
                        tokens.push(token);
                    }
                    (
                        GenericTokenResponse::PrivateRistretto255(response),
                        GenericTokenState::PrivateRistretto255(state),
                    ) => {
                        let token = response
                            .issue_token(state)
                            .map(GenericToken::from_private_ristretto)?;
                        tokens.push(token);
                    }
                    _ => {
                        return Err(IssueTokenError::InvalidTokenResponse);
                    }
                }
            }
        }

        Ok(tokens)
    }
}
