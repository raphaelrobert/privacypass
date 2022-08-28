//! # Publicly Verifiable Tokens

use sha2::{Digest, Sha256};
use typenum::U64;

use crate::{auth::authorize::Token, KeyId, Nonce, TokenKeyId, TokenType};

pub mod client;
pub mod server;

/// Publicly Verifiable Token alias
pub type PublicToken = Token<U64>;
pub use blind_rsa_signatures::PublicKey;

use self::server::serialize_public_key;

fn public_key_to_key_id(public_key: &PublicKey) -> KeyId {
    let public_key = serialize_public_key(public_key);
    let mut hasher = Sha256::new();
    hasher.update((TokenType::Batched as u16).to_be_bytes().as_slice());
    hasher.update(public_key);
    let key_id = hasher.finalize();
    key_id.into()
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
    blinded_msg: Vec<u8>,
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
    blind_sig: Vec<u8>,
}
