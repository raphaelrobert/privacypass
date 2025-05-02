//! # Privately Verifiable Tokens

pub mod client;
pub mod server;

use client::BatchTokenRequestBuilder;
use p384::NistP384;
use std::io::Read;
use tls_codec::{Deserialize, Serialize, Size};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
use voprf::Ristretto255;

use crate::{ChallengeDigest, TokenType, common::errors::SerializationError};

/// Arbitrary token
#[derive(Debug)]
pub enum ArbitraryBatchToken {
    /// Private p384 token
    PrivateP384(Box<crate::private_tokens::PrivateToken<NistP384>>),
    /// Public token
    Public(Box<crate::public_tokens::PublicToken>),
    /// Private ristretto255 token
    PrivateRistretto255(Box<crate::private_tokens::PrivateToken<Ristretto255>>),
}

impl ArbitraryBatchToken {
    /// Get the token type
    pub fn token_type(&self) -> TokenType {
        match self {
            ArbitraryBatchToken::PrivateP384(_) => TokenType::PrivateP384,
            ArbitraryBatchToken::Public(_) => TokenType::Public,
            ArbitraryBatchToken::PrivateRistretto255(_) => TokenType::PrivateRistretto255,
        }
    }

    /// Get the challenge
    pub fn challenge_digest(&self) -> &ChallengeDigest {
        match self {
            ArbitraryBatchToken::PrivateP384(token) => token.challenge_digest(),
            ArbitraryBatchToken::Public(token) => token.challenge_digest(),
            ArbitraryBatchToken::PrivateRistretto255(token) => token.challenge_digest(),
        }
    }
}

impl ArbitraryBatchToken {
    pub(crate) fn from_private_p384(tok: crate::private_tokens::PrivateToken<NistP384>) -> Self {
        ArbitraryBatchToken::PrivateP384(Box::new(tok))
    }
    pub(crate) fn from_public(tok: crate::public_tokens::PublicToken) -> Self {
        ArbitraryBatchToken::Public(Box::new(tok))
    }
    pub(crate) fn from_private_ristretto(
        tok: crate::private_tokens::PrivateToken<Ristretto255>,
    ) -> Self {
        ArbitraryBatchToken::PrivateRistretto255(Box::new(tok))
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

/// Arbitrary Batch TokenResponse as specified in the spec:
///
/// ```c
/// struct {
///     optional TokenResponse token_responses<V>;
///   } BatchTokenRequest
/// ```
#[repr(u16)]
#[derive(Debug, Clone, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub enum ArbitraryBatchTokenResponse {
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
    pub token_response: Option<ArbitraryBatchTokenResponse>,
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
