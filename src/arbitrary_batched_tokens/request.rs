//! Request implementation of the  Arbitrary Batched Token protocol.

use p384::NistP384;
use std::io::Read;
use tls_codec::{Deserialize, Serialize, Size};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
use voprf::Ristretto255;

use crate::{TokenType, common::errors::SerializationError};

/// State that is kept between the token requests and token responses.
#[derive(Debug)]
pub enum ArbitraryBatchTokenState {
    /// Private p384 token state
    PrivateP384(Box<crate::private_tokens::TokenState<NistP384>>),
    /// Public token state
    Public(Box<crate::public_tokens::TokenState>),
    /// Private ristretto255 token state
    PrivateRistretto255(Box<crate::private_tokens::request::TokenState<Ristretto255>>),
}

impl From<crate::private_tokens::TokenState<NistP384>> for ArbitraryBatchTokenState {
    fn from(state: crate::private_tokens::TokenState<NistP384>) -> Self {
        ArbitraryBatchTokenState::PrivateP384(Box::new(state))
    }
}

impl From<crate::private_tokens::TokenState<Ristretto255>> for ArbitraryBatchTokenState {
    fn from(state: crate::private_tokens::TokenState<Ristretto255>) -> Self {
        ArbitraryBatchTokenState::PrivateRistretto255(Box::new(state))
    }
}

impl From<crate::public_tokens::TokenState> for ArbitraryBatchTokenState {
    fn from(state: crate::public_tokens::TokenState) -> Self {
        ArbitraryBatchTokenState::Public(Box::new(state))
    }
}

/// Token states that are kept between the token requests and token responses.
#[derive(Debug)]
pub struct TokenStates {
    pub(crate) token_states: Vec<ArbitraryBatchTokenState>,
}

/// Builder for batch token requests.
#[derive(Debug, Default)]
pub struct BatchTokenRequestBuilder {
    token_requests: Vec<ArbitraryBatchTokenRequest>,
    token_states: Vec<ArbitraryBatchTokenState>,
}

impl BatchTokenRequestBuilder {
    /// Add a token request to the batch.
    #[must_use]
    pub fn add_token_request(
        mut self,
        token_request: ArbitraryBatchTokenRequest,
        token_state: ArbitraryBatchTokenState,
    ) -> Self {
        self.token_requests.push(token_request);
        self.token_states.push(token_state);
        self
    }

    /// Build the batch token request.
    #[must_use]
    pub fn build(self) -> (BatchTokenRequest, TokenStates) {
        (
            BatchTokenRequest {
                token_requests: self.token_requests,
            },
            TokenStates {
                token_states: self.token_states,
            },
        )
    }
}

/// Arbitrary Batch TokenRequest as specified in the spec:
///
/// ```c
/// struct {
///     uint16_t token_type;
///     select (token_type) {
///        case (0x0001): /* Type VOPRF(P-384, SHA-384), RFC 9578 */
///           uint8_t truncated_token_key_id;
///           uint8_t blinded_msg[Ne];
///        case (0x0002): /* Type Blind RSA (2048-bit), RFC 9578 */
///           uint8_t truncated_token_key_id;
///           uint8_t blinded_msg[Nk];
///     }
///  } TokenRequest;
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum ArbitraryBatchTokenRequest {
    /// Type VOPRF(P-384, SHA-384), RFC 9578
    PrivateP384(Box<crate::private_tokens::TokenRequest<NistP384>>),
    /// Type Blind RSA (2048-bit), RFC 9578
    Public(Box<crate::public_tokens::TokenRequest>),
    /// Type VOPRF(Ristretto255, SHA-512), RFC XXXX
    PrivateRistretto255(Box<crate::private_tokens::TokenRequest<Ristretto255>>),
}

impl From<crate::private_tokens::TokenRequest<NistP384>> for ArbitraryBatchTokenRequest {
    fn from(token_request: crate::private_tokens::TokenRequest<NistP384>) -> Self {
        ArbitraryBatchTokenRequest::PrivateP384(Box::new(token_request))
    }
}

impl From<crate::public_tokens::TokenRequest> for ArbitraryBatchTokenRequest {
    fn from(token_request: crate::public_tokens::TokenRequest) -> Self {
        ArbitraryBatchTokenRequest::Public(Box::new(token_request))
    }
}

impl From<crate::private_tokens::TokenRequest<Ristretto255>> for ArbitraryBatchTokenRequest {
    fn from(token_request: crate::private_tokens::TokenRequest<Ristretto255>) -> Self {
        ArbitraryBatchTokenRequest::PrivateRistretto255(Box::new(token_request))
    }
}

/// Token response as specified in the spec:
///
/// ```c
///  struct {
///    TokenRequest token_requests<V>;
///  } BatchTokenRequest
/// ```
#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct BatchTokenRequest {
    /// Token requests
    pub token_requests: Vec<ArbitraryBatchTokenRequest>,
}

impl BatchTokenRequest {
    /// Create a new `BatchTokenRequest` from a byte slice.
    ///
    /// # Errors
    /// Returns `SerializationError::InvalidData` if the byte slice is not valid.
    pub fn try_from_bytes(mut bytes: &[u8]) -> Result<Self, SerializationError> {
        Self::tls_deserialize(&mut bytes).map_err(|_| SerializationError::InvalidData)
    }

    /// Create a builder for `BatchTokenRequest`.
    pub fn builder() -> BatchTokenRequestBuilder {
        BatchTokenRequestBuilder::default()
    }
}

impl Size for ArbitraryBatchTokenRequest {
    fn tls_serialized_len(&self) -> usize {
        match self {
            ArbitraryBatchTokenRequest::PrivateP384(token_request) => {
                token_request.tls_serialized_len()
            }
            ArbitraryBatchTokenRequest::Public(token_request) => token_request.tls_serialized_len(),
            ArbitraryBatchTokenRequest::PrivateRistretto255(token_request) => {
                token_request.tls_serialized_len()
            }
        }
    }
}

impl Serialize for ArbitraryBatchTokenRequest {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        match self {
            ArbitraryBatchTokenRequest::PrivateP384(token_request) => {
                token_request.tls_serialize(writer)
            }
            ArbitraryBatchTokenRequest::Public(token_request) => {
                token_request.tls_serialize(writer)
            }
            ArbitraryBatchTokenRequest::PrivateRistretto255(token_request) => {
                token_request.tls_serialize(writer)
            }
        }
    }
}

impl Deserialize for ArbitraryBatchTokenRequest {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        // Peek into the first two octets to determine the type
        let mut peeked = [0u8; 2];
        bytes.read_exact(&mut peeked)?;

        let token_type = TokenType::tls_deserialize(&mut peeked.as_slice())?;
        let mut all_bytes = (peeked).chain(bytes);

        match token_type {
            TokenType::PrivateP384 => {
                let token_request =
                    crate::private_tokens::TokenRequest::tls_deserialize(&mut all_bytes)?;
                Ok(ArbitraryBatchTokenRequest::PrivateP384(Box::new(
                    token_request,
                )))
            }
            TokenType::Public => {
                let token_request =
                    crate::public_tokens::TokenRequest::tls_deserialize(&mut all_bytes)?;
                Ok(ArbitraryBatchTokenRequest::Public(Box::new(token_request)))
            }
            TokenType::PrivateRistretto255 => {
                let token_request =
                    crate::private_tokens::TokenRequest::tls_deserialize(&mut all_bytes)?;
                Ok(ArbitraryBatchTokenRequest::PrivateRistretto255(Box::new(
                    token_request,
                )))
            }
        }
    }
}
