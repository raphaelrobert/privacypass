//! # Publicly Verifiable Tokens

use std::io::Write;

use sha2::{Digest, Sha256};
use tls_codec::{Deserialize, Serialize, Size};
use typenum::U64;

use crate::{auth::authorize::Token, KeyId, Nonce, TokenKeyId, TokenType};

pub mod client;
pub mod server;

/// Publicly Verifiable Token alias
pub type PublicToken = Token<U64>;
pub use blind_rsa_signatures::PublicKey;

use self::server::serialize_public_key;

/// Size of the authenticator
pub const NK: usize = 256;

/// Converts a public key to a token key ID
pub fn public_key_to_token_key_id(public_key: &PublicKey) -> TokenKeyId {
    key_id_to_token_key_id(&public_key_to_key_id(public_key))
}

fn public_key_to_key_id(public_key: &PublicKey) -> KeyId {
    let public_key = serialize_public_key(public_key);

    Sha256::digest(public_key).into()
}

fn key_id_to_token_key_id(key_id: &KeyId) -> TokenKeyId {
    *key_id.iter().last().unwrap_or(&0)
}

/// Token request as specified in the spec:
///
/// ```c
/// struct {
///     uint16_t token_type = 0x0002;
///     uint8_t token_key_id;
///     uint8_t blinded_msg[Nk];
///  } TokenRequest;
/// ```

#[derive(Debug)]
pub struct TokenRequest {
    token_type: TokenType,
    token_key_id: u8,
    blinded_msg: [u8; NK],
}

/// Token response as specified in the spec:
///
/// ```c
/// struct {
///     uint8_t blind_sig[Nk];
///  } TokenResponse;
/// ```

#[derive(Debug)]
pub struct TokenResponse {
    blind_sig: [u8; NK],
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
        let mut blinded_msg = [0u8; NK];
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
        self.blind_sig.len()
    }
}

impl Serialize for TokenResponse {
    fn tls_serialize<W: Write>(
        &self,
        writer: &mut W,
    ) -> std::result::Result<usize, tls_codec::Error> {
        Ok(writer.write(&self.blind_sig)?)
    }
}

impl Deserialize for TokenResponse {
    fn tls_deserialize<R: std::io::Read>(
        bytes: &mut R,
    ) -> std::result::Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let mut blind_sig = [0u8; NK];
        bytes.read_exact(&mut blind_sig)?;

        Ok(Self { blind_sig })
    }
}
