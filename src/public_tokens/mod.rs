//! # Publicly Verifiable Tokens

use blind_rsa_signatures::{Deterministic, PSS, Sha384};
use sha2::{Digest, Sha256};
use typenum::U256;

use blind_rsa_signatures::Error as BlindRsaError;

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
/// Publicly Verifiable Token public key type alias (SHA-384, PSS, Deterministic).
pub type PublicKey = blind_rsa_signatures::PublicKey<Sha384, PSS, Deterministic>;

use self::server::serialize_public_key;

/// Size of the authenticator
pub const NK: usize = 256;

/// Converts a public key to a truncated token key ID.
///
/// # Errors
/// Returns an error if the public key cannot be serialized.
pub fn public_key_to_truncated_token_key_id(
    public_key: &PublicKey,
) -> Result<TruncatedTokenKeyId, BlindRsaError> {
    Ok(truncate_token_key_id(&public_key_to_token_key_id(
        public_key,
    )?))
}

fn public_key_to_token_key_id(public_key: &PublicKey) -> Result<TokenKeyId, BlindRsaError> {
    let public_key = serialize_public_key(public_key)?;

    Ok(Sha256::digest(public_key).into())
}
