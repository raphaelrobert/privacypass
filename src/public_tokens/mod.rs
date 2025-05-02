//! # Publicly Verifiable Tokens

use sha2::{Digest, Sha256};
use typenum::U256;

use crate::{TokenKeyId, TruncatedTokenKeyId, auth::authorize::Token, truncate_token_key_id};

pub mod request;
pub mod response;
pub mod server;

#[cfg(feature = "kat")]
pub mod det_rng;

pub use request::*;
pub use response::*;

/// Publicly Verifiable Token alias
pub type PublicToken = Token<U256>;
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
