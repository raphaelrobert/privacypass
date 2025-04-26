//! # Privately Verifiable Tokens

pub mod client;
pub mod server;

use client::BatchTokenRequestBuilder;
use std::io::Read;
use thiserror::Error;
use tls_codec::{Deserialize, Serialize, Size};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::{ChallengeDigest, TokenType};

/// Arbitrary token
#[derive(Debug)]
pub enum ArbitraryBatchToken {
    /// Private token
    PrivateToken(Box<crate::private_tokens::PrivateToken>),
    /// Public token
    PublicToken(Box<crate::public_tokens::PublicToken>),
}

impl ArbitraryBatchToken {
    /// Get the token type
    pub fn token_type(&self) -> TokenType {
        match self {
            ArbitraryBatchToken::PrivateToken(_) => TokenType::PrivateToken,
            ArbitraryBatchToken::PublicToken(_) => TokenType::PublicToken,
        }
    }

    /// Get the challenge
    pub fn challenge_digest(&self) -> &ChallengeDigest {
        match self {
            ArbitraryBatchToken::PrivateToken(token) => token.challenge_digest(),
            ArbitraryBatchToken::PublicToken(token) => token.challenge_digest(),
        }
    }
}

impl From<crate::private_tokens::PrivateToken> for ArbitraryBatchToken {
    fn from(token: crate::private_tokens::PrivateToken) -> Self {
        ArbitraryBatchToken::PrivateToken(Box::new(token))
    }
}

impl From<crate::public_tokens::PublicToken> for ArbitraryBatchToken {
    fn from(token: crate::public_tokens::PublicToken) -> Self {
        ArbitraryBatchToken::PublicToken(Box::new(token))
    }
}

/// Serialization error
#[derive(Error, Debug)]
pub enum SerializationError {
    #[error("Invalid serialized data")]
    /// Invalid serialized data
    InvalidData,
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
    PrivateTokenRequest(Box<crate::private_tokens::TokenRequest>),
    /// Type Blind RSA (2048-bit), RFC 9578
    PublicTokenRequest(Box<crate::public_tokens::TokenRequest>),
}

impl From<crate::private_tokens::TokenRequest> for ArbitraryBatchTokenRequest {
    fn from(token_request: crate::private_tokens::TokenRequest) -> Self {
        ArbitraryBatchTokenRequest::PrivateTokenRequest(Box::new(token_request))
    }
}

impl From<crate::public_tokens::TokenRequest> for ArbitraryBatchTokenRequest {
    fn from(token_request: crate::public_tokens::TokenRequest) -> Self {
        ArbitraryBatchTokenRequest::PublicTokenRequest(Box::new(token_request))
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
            ArbitraryBatchTokenRequest::PrivateTokenRequest(token_request) => {
                token_request.tls_serialized_len()
            }
            ArbitraryBatchTokenRequest::PublicTokenRequest(token_request) => {
                token_request.tls_serialized_len()
            }
        }
    }
}

impl Serialize for ArbitraryBatchTokenRequest {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        match self {
            ArbitraryBatchTokenRequest::PrivateTokenRequest(token_request) => {
                token_request.tls_serialize(writer)
            }
            ArbitraryBatchTokenRequest::PublicTokenRequest(token_request) => {
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
            TokenType::PrivateToken => {
                let token_request =
                    crate::private_tokens::TokenRequest::tls_deserialize(&mut all_bytes)?;
                Ok(ArbitraryBatchTokenRequest::PrivateTokenRequest(Box::new(
                    token_request,
                )))
            }
            TokenType::PublicToken => {
                let token_request =
                    crate::public_tokens::TokenRequest::tls_deserialize(&mut all_bytes)?;
                Ok(ArbitraryBatchTokenRequest::PublicTokenRequest(Box::new(
                    token_request,
                )))
            }
            _ => Err(tls_codec::Error::DecodingError(
                "Invalid token type".to_string(),
            )),
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
    #[tls_codec(discriminant = "TokenType::PrivateToken")]
    PrivateTokenResponse(Box<crate::private_tokens::TokenResponse>),
    /// Type Blind RSA (2048-bit), RFC 9578
    #[tls_codec(discriminant = "TokenType::PublicToken")]
    PublicTokenResponse(Box<crate::public_tokens::TokenResponse>),
}

/// Token response as specified in the spec:
///
/// ```c
/// struct {
///     TokenResponse token_response<V>; /* Defined by token_type */
///   } OptionalTokenResponse;
///```
#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
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
#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
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

/*
impl Size for ArbitraryBatchTokenResponse {
    fn tls_serialized_len(&self) -> usize {
        match self {
            ArbitraryBatchTokenResponse::PrivateTokenResponse(token_response) => {
                token_response.tls_serialized_len()
            }
            ArbitraryBatchTokenResponse::PublicTokenResponse(token_response) => {
                token_response.tls_serialized_len()
            }
        }
    }
}

impl Serialize for ArbitraryBatchTokenResponse {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        match self {
            ArbitraryBatchTokenResponse::PrivateTokenResponse(token_response) => {
                token_response.tls_serialize(writer)
            }
            ArbitraryBatchTokenResponse::PublicTokenResponse(token_response) => {
                token_response.tls_serialize(writer)
            }
        }
    }
}

impl Deserialize for ArbitraryBatchTokenResponse {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        // Peek into the first two octets to determine the type
        let mut peeked = [0u8; 2];
        bytes.read_exact(&mut peeked)?;

        let token_type = TokenType::tls_deserialize(&mut peeked.as_slice())?;
        let mut all_bytes = (peeked).chain(bytes);

        match token_type {
            TokenType::PrivateToken => {
                let token_response =
                    crate::private_tokens::TokenResponse::tls_deserialize(&mut all_bytes)?;
                Ok(ArbitraryBatchTokenResponse::PrivateTokenResponse(Box::new(
                    token_response,
                )))
            }
            TokenType::PublicToken => {
                let token_response =
                    crate::public_tokens::TokenResponse::tls_deserialize(&mut all_bytes)?;
                Ok(ArbitraryBatchTokenResponse::PublicTokenResponse(Box::new(
                    token_response,
                )))
            }
            _ => Err(tls_codec::Error::DecodingError(
                "Invalid token type".to_string(),
            )),
        }
    }
}
*/
/*
#[cfg(test)]
#[tokio::test]
async fn arbitrary_codec() {
    use rand::{rngs::OsRng, RngCore};

    let key_store = crate::test_utils::private_memory_stores::MemoryKeyStore::default();
    let server = crate::private_tokens::server::Server::new();

    let public_key = server.create_keypair(&key_store).await.unwrap();

    let client = crate::private_tokens::client::Client::new(public_key);

    let redemption_context = if OsRng.next_u32() % 2 == 0 {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Some(bytes)
    } else {
        None
    };

    let kat_token_challenge = TokenChallenge::new(
        crate::TokenType::PrivateToken,
        "Issuer Name",
        redemption_context,
        &["a".to_string(), "b".to_string(), "c".to_string()],
    );

    let (kat_token_request, _token_state) =
        client.issue_token_request(&kat_token_challenge).unwrap();

    let kat_token_response = server
        .issue_token_response(&key_store, kat_token_request.clone())
        .await
        .unwrap();

    let arbitrary_batch_token_request =
        ArbitraryBatchTokenRequest::PrivateTokenRequest(Box::new(kat_token_request.clone()));
    let mut bytes = Vec::new();
    arbitrary_batch_token_request
        .tls_serialize(&mut bytes)
        .unwrap();
    let deserialized = ArbitraryBatchTokenRequest::tls_deserialize(&mut bytes.as_slice()).unwrap();
    assert_eq!(arbitrary_batch_token_request, deserialized);

    let arbitrary_batch_token_response =
        ArbitraryBatchTokenResponse::PrivateTokenResponse(Box::new(kat_token_response.clone()));
    let mut bytes = Vec::new();
    arbitrary_batch_token_response
        .tls_serialize(&mut bytes)
        .unwrap();
    let deserialized = ArbitraryBatchTokenResponse::tls_deserialize(&mut bytes.as_slice()).unwrap();
    assert_eq!(arbitrary_batch_token_response, deserialized);

    let optional_token_response = OptionalTokenResponse {
        token_response: Some(ArbitraryBatchTokenResponse::PrivateTokenResponse(Box::new(
            kat_token_response.clone(),
        ))),
    };
    let mut bytes = Vec::new();
    optional_token_response.tls_serialize(&mut bytes).unwrap();
    let deserialized = OptionalTokenResponse::tls_deserialize(&mut bytes.as_slice()).unwrap();
    assert_eq!(optional_token_response, deserialized);

    let batch_token_request = BatchTokenRequest {
        token_requests: vec![ArbitraryBatchTokenRequest::PrivateTokenRequest(Box::new(
            kat_token_request.clone(),
        ))],
    };
    let mut bytes = Vec::new();
    batch_token_request.tls_serialize(&mut bytes).unwrap();
    let deserialized = BatchTokenRequest::try_from_bytes(&bytes).unwrap();
    assert_eq!(batch_token_request, deserialized);

    let batch_token_response = BatchTokenResponse {
        token_responses: vec![OptionalTokenResponse {
            token_response: Some(ArbitraryBatchTokenResponse::PrivateTokenResponse(Box::new(
                kat_token_response.clone(),
            ))),
        }],
    };
    let mut bytes = Vec::new();
    batch_token_response.tls_serialize(&mut bytes).unwrap();

    let deserialized = BatchTokenResponse::tls_deserialize(&mut bytes.as_slice()).unwrap();
    assert_eq!(batch_token_response, deserialized);
}
 */
