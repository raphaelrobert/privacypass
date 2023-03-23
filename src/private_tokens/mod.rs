//! # Privately Verifiable Tokens

pub mod client;
pub mod server;

use p384::NistP384;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tls_codec::Deserialize;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
use typenum::U48;
pub use voprf::*;

use crate::{auth::authorize::Token, KeyId, Nonce, TokenKeyId, TokenType};

use self::server::serialize_public_key;

/// Size of serialized element
pub const NE: usize = 49;
/// Size of serializes scalar
pub const NS: usize = 48;
/// Size of the authenticator
pub const NK: usize = 48;

/// Privately Verifiable Token alias
pub type PrivateToken = Token<U48>;
/// Public key alias
pub type PublicKey = <NistP384 as Group>::Elem;

/// Convert a public key to a token key ID.
pub fn public_key_to_token_key_id(public_key: &PublicKey) -> TokenKeyId {
    key_id_to_token_key_id(&public_key_to_key_id(public_key))
}

fn public_key_to_key_id(public_key: &PublicKey) -> KeyId {
    let public_key = serialize_public_key(*public_key);

    Sha256::digest(public_key).into()
}

fn key_id_to_token_key_id(key_id: &KeyId) -> TokenKeyId {
    *key_id.iter().last().unwrap_or(&0)
}

/// Serialization error
#[derive(Error, Debug)]
pub enum SerializationError {
    #[error("Invalid serialized data")]
    /// Invalid serialized data
    InvalidData,
}

/// Token request as specified in the spec:
///
/// ```c
/// struct {
///     uint16_t token_type = 0x0001;
///     uint8_t token_key_id;
///     uint8_t blinded_msg[Ne];
///  } TokenRequest;
/// ```
#[derive(Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct TokenRequest {
    token_type: TokenType,
    token_key_id: u8,
    blinded_msg: [u8; NE],
}

/// Token response as specified in the spec:
///
/// ```c
/// struct {
///     uint8_t evaluate_msg[Ne];
///     uint8_t evaluate_proof[Ns+Ns];
///  } TokenResponse;
/// ```
#[derive(Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct TokenResponse {
    evaluate_msg: [u8; NE],
    evaluate_proof: [u8; NS + NS],
}

impl TokenResponse {
    /// Create a new `TokenResponse` from a byte slice.
    ///
    /// # Errors
    /// Returns `SerializationError::InvalidData` if the byte slice is not valid.
    pub fn try_from_bytes(mut bytes: &[u8]) -> Result<Self, SerializationError> {
        Self::tls_deserialize(&mut bytes).map_err(|_| SerializationError::InvalidData)
    }
}
