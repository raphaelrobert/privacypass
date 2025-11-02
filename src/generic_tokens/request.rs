//! Request implementation of the  Generic Token protocol.

use p384::NistP384;
use std::io::Read;
use tls_codec::{Deserialize, Serialize, Size};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
use voprf::Ristretto255;

use crate::{TokenType, common::errors::SerializationError};

/// State that is kept between the token requests and token responses.
#[derive(Debug)]
pub enum GenericTokenState {
    /// Private p384 token state
    PrivateP384(Box<crate::private_tokens::TokenState<NistP384>>),
    /// Public token state
    Public(Box<crate::public_tokens::TokenState>),
    /// Private ristretto255 token state
    PrivateRistretto255(Box<crate::private_tokens::request::TokenState<Ristretto255>>),
}

impl From<crate::private_tokens::TokenState<NistP384>> for GenericTokenState {
    fn from(state: crate::private_tokens::TokenState<NistP384>) -> Self {
        GenericTokenState::PrivateP384(Box::new(state))
    }
}

impl From<crate::private_tokens::TokenState<Ristretto255>> for GenericTokenState {
    fn from(state: crate::private_tokens::TokenState<Ristretto255>) -> Self {
        GenericTokenState::PrivateRistretto255(Box::new(state))
    }
}

impl From<crate::public_tokens::TokenState> for GenericTokenState {
    fn from(state: crate::public_tokens::TokenState) -> Self {
        GenericTokenState::Public(Box::new(state))
    }
}

/// Token states that are kept between the token requests and token responses.
#[derive(Debug)]
pub struct TokenStates {
    pub(crate) token_states: Vec<GenericTokenState>,
}

/// Builder for generic batch token requests.
#[derive(Debug, Default)]
pub struct GenericBatchTokenRequestBuilder {
    token_requests: Vec<GenericTokenRequest>,
    token_states: Vec<GenericTokenState>,
}

impl GenericBatchTokenRequestBuilder {
    /// Add a token request to the batch.
    #[must_use]
    pub fn add_token_request(
        mut self,
        token_request: GenericTokenRequest,
        token_state: GenericTokenState,
    ) -> Self {
        self.token_requests.push(token_request);
        self.token_states.push(token_state);
        self
    }

    /// Build the generic batch token request.
    #[must_use]
    pub fn build(self) -> (GenericBatchTokenRequest, TokenStates) {
        (
            GenericBatchTokenRequest {
                token_requests: self.token_requests,
            },
            TokenStates {
                token_states: self.token_states,
            },
        )
    }
}

/// Generic TokenRequest as specified in the spec:
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
pub enum GenericTokenRequest {
    /// Type VOPRF(P-384, SHA-384), RFC 9578
    PrivateP384(Box<crate::private_tokens::TokenRequest<NistP384>>),
    /// Type Blind RSA (2048-bit), RFC 9578
    Public(Box<crate::public_tokens::TokenRequest>),
    /// Type VOPRF(Ristretto255, SHA-512), RFC XXXX
    PrivateRistretto255(Box<crate::private_tokens::TokenRequest<Ristretto255>>),
}

impl From<crate::private_tokens::TokenRequest<NistP384>> for GenericTokenRequest {
    fn from(token_request: crate::private_tokens::TokenRequest<NistP384>) -> Self {
        GenericTokenRequest::PrivateP384(Box::new(token_request))
    }
}

impl From<crate::public_tokens::TokenRequest> for GenericTokenRequest {
    fn from(token_request: crate::public_tokens::TokenRequest) -> Self {
        GenericTokenRequest::Public(Box::new(token_request))
    }
}

impl From<crate::private_tokens::TokenRequest<Ristretto255>> for GenericTokenRequest {
    fn from(token_request: crate::private_tokens::TokenRequest<Ristretto255>) -> Self {
        GenericTokenRequest::PrivateRistretto255(Box::new(token_request))
    }
}

/// Token response as specified in the spec:
///
/// ```c
/// struct {
///      GenericTokenRequest generic_token_requests<V>;
/// } GenericBatchTokenRequest
/// ```
#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct GenericBatchTokenRequest {
    /// Token requests
    pub token_requests: Vec<GenericTokenRequest>,
}

impl GenericBatchTokenRequest {
    /// Create a new `BatchTokenRequest` from a byte slice.
    ///
    /// # Errors
    /// Returns `SerializationError::InvalidData` if the byte slice is not valid.
    pub fn try_from_bytes(mut bytes: &[u8]) -> Result<Self, SerializationError> {
        Self::tls_deserialize(&mut bytes)
            .map_err(|source| SerializationError::InvalidData { source })
    }

    /// Create a builder for `BatchTokenRequest`.
    pub fn builder() -> GenericBatchTokenRequestBuilder {
        GenericBatchTokenRequestBuilder::default()
    }
}

impl Size for GenericTokenRequest {
    fn tls_serialized_len(&self) -> usize {
        match self {
            GenericTokenRequest::PrivateP384(token_request) => token_request.tls_serialized_len(),
            GenericTokenRequest::Public(token_request) => token_request.tls_serialized_len(),
            GenericTokenRequest::PrivateRistretto255(token_request) => {
                token_request.tls_serialized_len()
            }
        }
    }
}

impl Serialize for GenericTokenRequest {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        match self {
            GenericTokenRequest::PrivateP384(token_request) => token_request.tls_serialize(writer),
            GenericTokenRequest::Public(token_request) => token_request.tls_serialize(writer),
            GenericTokenRequest::PrivateRistretto255(token_request) => {
                token_request.tls_serialize(writer)
            }
        }
    }
}

impl Deserialize for GenericTokenRequest {
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
                Ok(GenericTokenRequest::PrivateP384(Box::new(token_request)))
            }
            TokenType::Public => {
                let token_request =
                    crate::public_tokens::TokenRequest::tls_deserialize(&mut all_bytes)?;
                Ok(GenericTokenRequest::Public(Box::new(token_request)))
            }
            TokenType::PrivateRistretto255 => {
                let token_request =
                    crate::private_tokens::TokenRequest::tls_deserialize(&mut all_bytes)?;
                Ok(GenericTokenRequest::PrivateRistretto255(Box::new(
                    token_request,
                )))
            }
        }
    }
}
