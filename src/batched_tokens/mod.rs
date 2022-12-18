//! # Batched tokens

pub mod client;
pub mod server;

use sha2::{Digest, Sha256};
use std::io::Write;
use thiserror::Error;
use tls_codec::{Deserialize, Serialize, Size, TlsVecU16};
use typenum::U64;
pub use voprf::*;

use crate::{auth::authorize::Token, KeyId, Nonce, TokenKeyId, TokenType};

use self::server::serialize_public_key;

/// Batched token alias
pub type BatchedToken = Token<U64>;
/// Public key alias
pub type PublicKey = <Ristretto255 as Group>::Elem;

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

/// Blinded element as specified in the spec:
///
/// ```c
/// struct {
///     uint8_t blinded_element[Ne];
/// } BlindedElement;
/// ```

#[derive(Debug)]
pub struct BlindedElement {
    blinded_element: [u8; 32],
}

/// Token request as specified in the spec:
///
/// ```c
/// struct {
///     uint16_t token_type = 0xF91A;
///     uint8_t token_key_id;
///     BlindedElement blinded_element[Nr];
/// } TokenRequest;
/// ```

#[derive(Debug)]
pub struct TokenRequest {
    token_type: TokenType,
    token_key_id: TokenKeyId,
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

#[derive(Debug)]
pub struct EvaluatedElement {
    evaluated_element: [u8; 32],
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
pub struct TokenResponse {
    evaluated_elements: TlsVecU16<EvaluatedElement>,
    evaluated_proof: [u8; 64],
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

// === TLS codecs ===

impl Size for BlindedElement {
    fn tls_serialized_len(&self) -> usize {
        32
    }
}

impl Serialize for BlindedElement {
    fn tls_serialize<W: Write>(
        &self,
        writer: &mut W,
    ) -> std::result::Result<usize, tls_codec::Error> {
        Ok(writer.write(&self.blinded_element)?)
    }
}

impl Deserialize for BlindedElement {
    fn tls_deserialize<R: std::io::Read>(
        bytes: &mut R,
    ) -> std::result::Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let mut blinded_element = [0u8; 32];
        bytes.read_exact(&mut blinded_element)?;
        Ok(Self { blinded_element })
    }
}

impl Size for EvaluatedElement {
    fn tls_serialized_len(&self) -> usize {
        32
    }
}

impl Serialize for EvaluatedElement {
    fn tls_serialize<W: Write>(
        &self,
        writer: &mut W,
    ) -> std::result::Result<usize, tls_codec::Error> {
        Ok(writer.write(&self.evaluated_element)?)
    }
}

impl Deserialize for EvaluatedElement {
    fn tls_deserialize<R: std::io::Read>(
        bytes: &mut R,
    ) -> std::result::Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let mut evaluated_element = [0u8; 32];
        bytes.read_exact(&mut evaluated_element)?;
        Ok(Self { evaluated_element })
    }
}

impl Size for TokenRequest {
    fn tls_serialized_len(&self) -> usize {
        self.token_type.tls_serialized_len()
            + self.token_key_id.tls_serialized_len()
            + self
                .blinded_elements
                .iter()
                .map(tls_codec::Size::tls_serialized_len)
                .sum::<usize>()
    }
}

impl Serialize for TokenRequest {
    fn tls_serialize<W: Write>(
        &self,
        writer: &mut W,
    ) -> std::result::Result<usize, tls_codec::Error> {
        Ok(self.token_type.tls_serialize(writer)?
            + self.token_key_id.tls_serialize(writer)?
            + self.blinded_elements.tls_serialize(writer)?)
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
        let token_key_id = TokenKeyId::tls_deserialize(bytes)?;
        let blinded_elements = TlsVecU16::tls_deserialize(bytes)?;

        Ok(Self {
            token_type,
            token_key_id,
            blinded_elements,
        })
    }
}

impl Size for TokenResponse {
    fn tls_serialized_len(&self) -> usize {
        self.evaluated_elements.tls_serialized_len() + self.evaluated_proof.tls_serialized_len()
    }
}

impl Serialize for TokenResponse {
    fn tls_serialize<W: Write>(
        &self,
        writer: &mut W,
    ) -> std::result::Result<usize, tls_codec::Error> {
        Ok(self.evaluated_elements.tls_serialize(writer)?
            + self.evaluated_proof.tls_serialize(writer)?)
    }
}

impl Deserialize for TokenResponse {
    fn tls_deserialize<R: std::io::Read>(
        bytes: &mut R,
    ) -> std::result::Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let evaluated_elements = TlsVecU16::tls_deserialize(bytes)?;
        let mut evaluated_proof = [0u8; 64];
        bytes.read_exact(&mut evaluated_proof)?;
        Ok(Self {
            evaluated_elements,
            evaluated_proof,
        })
    }
}
