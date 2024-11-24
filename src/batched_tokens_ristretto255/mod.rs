//! # Batched tokens

pub mod client;
pub mod server;

use sha2::{Digest, Sha256};
use thiserror::Error;
use tls_codec::{Deserialize, TlsVecU16};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
use typenum::U64;
pub use voprf::*;

use crate::{auth::authorize::Token, Nonce, TokenKeyId, TokenType, TruncatedTokenKeyId};

use self::server::serialize_public_key;

/// Size of serialized element
pub const NE: usize = 32;
/// Size of serializes scalar
pub const NS: usize = 32;
/// Size of the authenticator
pub const NK: usize = 64;

/// Batched token alias
pub type BatchedToken = Token<U64>;
/// Public key alias
pub type PublicKey = <Ristretto255 as Group>::Elem;

fn public_key_to_token_key_id(public_key: &PublicKey) -> TokenKeyId {
    let public_key = serialize_public_key(*public_key);

    Sha256::digest(public_key).into()
}

fn truncate_token_key_id(token_key_id: &TokenKeyId) -> TruncatedTokenKeyId {
    *token_key_id.iter().last().unwrap_or(&0)
}

/// Serialization error
#[derive(Error, Debug)]
pub enum SerializationError {
    #[error("Invalid serialized data")]
    /// Invalid serialized data
    InvalidData,
}

/// Blinded element as specified in the spec:
///
/// ```c
/// struct {
///     uint8_t blinded_element[Ne];
/// } BlindedElement;
/// ```
#[derive(Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct BlindedElement {
    blinded_element: [u8; NE],
}

/// Token request as specified in the spec:
///
/// ```c
/// struct {
///     uint16_t token_type = 0xF91A;
///     uint8_t truncated_token_key_id;
///     BlindedElement blinded_element[Nr];
/// } TokenRequest;
/// ```
#[derive(Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct TokenRequest {
    token_type: TokenType,
    truncated_token_key_id: TruncatedTokenKeyId,
    blinded_elements: TlsVecU16<BlindedElement>,
}

impl TokenRequest {
    /// Returns the number of blinded elements
    #[must_use]
    pub fn nr(&self) -> usize {
        self.blinded_elements.len()
    }
}

/// Evaluated element as specified in the spec:
///
/// ```c
/// struct {
///     uint8_t evaluated_element[Ne];
/// } EvaluatedElement;
/// ```

#[derive(Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct EvaluatedElement {
    evaluated_element: [u8; NE],
}

/// Token response as specified in the spec:
///
/// ```c
/// struct {
///     EvaluatedElement evaluated_elements[Nr];
///     uint8_t evaluated_proof[Ns + Ns];
///  } TokenResponse;
/// ```
#[derive(Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct TokenResponse {
    evaluated_elements: TlsVecU16<EvaluatedElement>,
    evaluated_proof: [u8; NS + NS],
}

impl TokenResponse {
    /// Create a new `TokenResponse` from a byte slice.
    ///
    /// # Errors
    /// Returns `SerializationError::InvalidData` if the byte slice is not a
    /// valid `TokenResponse`.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        let mut bytes = bytes;
        Self::tls_deserialize(&mut bytes).map_err(|_| SerializationError::InvalidData)
    }
}
