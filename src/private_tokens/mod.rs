//! # Privately Verifiable Tokens

pub mod client;
pub mod server;

use p256::NistP256;
use sha2::{Digest, Sha256};
use std::io::Write;
use thiserror::Error;
use tls_codec::{Deserialize, Serialize, Size};
use typenum::U32;
pub use voprf::*;

use crate::{auth::authorize::Token, KeyId, Nonce, TokenKeyId, TokenType};

use self::server::serialize_public_key;

/// Privately Verifiable Token alias
pub type PrivateToken = Token<U32>;
/// Public key alias
pub type PublicKey = <NistP256 as Group>::Elem;

fn public_key_to_key_id(public_key: &PublicKey) -> KeyId {
    let public_key = serialize_public_key(*public_key);
    let mut hasher = Sha256::new();
    hasher.update((TokenType::Batched as u16).to_be_bytes().as_slice());
    hasher.update(public_key);
    let key_id = hasher.finalize();
    key_id.into()
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

#[derive(Debug)]
pub struct TokenRequest {
    token_type: TokenType,
    token_key_id: u8,
    blinded_msg: [u8; 33],
}

/// Token response as specified in the spec:
///
/// ```c
/// struct {
///     uint8_t evaluate_msg[Nk];
///     uint8_t evaluate_proof[Ns+Ns];
///  } TokenResponse;
/// ```

#[derive(Debug)]
pub struct TokenResponse {
    evaluate_msg: [u8; 33],
    evaluate_proof: [u8; 64],
}

impl TokenResponse {
    /// Create a new `TokenResponse` from a byte slice.
    ///
    /// # Errors
    /// Returns `SerializationError::InvalidData` if the byte slice is not valid.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        let mut bytes = bytes;
        Self::tls_deserialize(&mut bytes).map_err(|_| SerializationError::InvalidData)
    }
}

// === TLS codecs ===

impl Size for TokenRequest {
    fn tls_serialized_len(&self) -> usize {
        self.token_type.tls_serialized_len()
            + self.token_key_id.tls_serialized_len()
            + self.blinded_msg.len()
    }
}

impl Serialize for TokenRequest {
    fn tls_serialize<W: Write>(
        &self,
        writer: &mut W,
    ) -> std::result::Result<usize, tls_codec::Error> {
        Ok(self.token_type.tls_serialize(writer)?
            + self.token_key_id.tls_serialize(writer)?
            + writer.write(&self.blinded_msg)?)
    }
}

impl Deserialize for TokenRequest {
    fn tls_deserialize<R: std::io::Read>(
        bytes: &mut R,
    ) -> std::result::Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let token_type = TokenType::tls_deserialize(bytes)?;
        let token_key_id = u8::tls_deserialize(bytes)?;
        let mut blinded_msg = [0u8; 33];
        bytes.read_exact(&mut blinded_msg)?;

        Ok(Self {
            token_type,
            token_key_id,
            blinded_msg,
        })
    }
}

impl Size for TokenResponse {
    fn tls_serialized_len(&self) -> usize {
        self.evaluate_msg.len() + self.evaluate_proof.len()
    }
}

impl Serialize for TokenResponse {
    fn tls_serialize<W: Write>(
        &self,
        writer: &mut W,
    ) -> std::result::Result<usize, tls_codec::Error> {
        Ok(writer.write(&self.evaluate_msg)? + writer.write(&self.evaluate_proof)?)
    }
}

impl Deserialize for TokenResponse {
    fn tls_deserialize<R: std::io::Read>(
        bytes: &mut R,
    ) -> std::result::Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let mut evaluate_msg = [0u8; 33];
        bytes.read_exact(&mut evaluate_msg)?;

        let mut evaluate_proof = [0u8; 64];
        bytes.read_exact(&mut evaluate_proof)?;

        Ok(Self {
            evaluate_msg,
            evaluate_proof,
        })
    }
}
