//! # Publicly Verifiable Tokens

use sha2::{Digest, Sha256};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
use typenum::U64;

use crate::{auth::authorize::Token, Nonce, TokenKeyId, TokenType, TruncatedTokenKeyId};

pub mod client;
pub mod server;

/// Publicly Verifiable Token alias
pub type PublicToken = Token<U64>;
pub use blind_rsa_signatures::PublicKey;

use self::server::serialize_public_key;

/// Size of the authenticator
pub const NK: usize = 256;

/// Converts a public key to a token key ID
pub fn public_key_to_truncated_token_key_id(public_key: &PublicKey) -> TruncatedTokenKeyId {
    truncate_token_key_id(&public_key_to_token_key_id(public_key))
}

fn public_key_to_token_key_id(public_key: &PublicKey) -> TokenKeyId {
    let public_key = serialize_public_key(public_key);

    Sha256::digest(public_key).into()
}

fn truncate_token_key_id(token_key_id: &TokenKeyId) -> TruncatedTokenKeyId {
    *token_key_id.iter().last().unwrap_or(&0)
}

/// Token request as specified in the spec:
///
/// ```c
/// struct {
///     uint16_t token_type = 0x0002;
///     uint8_t truncated_token_key_id;
///     uint8_t blinded_msg[Nk];
///  } TokenRequest;
/// ```
#[derive(Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct TokenRequest {
    token_type: TokenType,
    truncated_token_key_id: u8,
    blinded_msg: [u8; NK],
}

/// Token response as specified in the spec:
///
/// ```c
/// struct {
///     uint8_t blind_sig[Nk];
///  } TokenResponse;
/// ```
#[derive(Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct TokenResponse {
    blind_sig: [u8; NK],
}
