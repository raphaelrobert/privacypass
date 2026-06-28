//! Types that used by private tokens

use sha2::{Digest, Sha256};
use std::fmt::Debug;
use voprf::{CipherSuite, Error, Group};

use crate::{TokenKeyId, TokenType, TruncatedTokenKeyId, truncate_token_key_id};

/// Trait for a cipher suite that can be used with the Privacy Pass protocol.
pub trait PrivateCipherSuite:
    CipherSuite<Group: Group<Elem: Send + Sync, Scalar: Send + Sync>>
    + PartialEq
    + Debug
    + Clone
    + Send
    + Sync
{
    /// Returns the token type for the cipher suite.
    fn token_type() -> TokenType;
}

impl PrivateCipherSuite for p384::NistP384 {
    fn token_type() -> TokenType {
        TokenType::PrivateP384
    }
}

impl PrivateCipherSuite for voprf::Ristretto255 {
    fn token_type() -> TokenType {
        TokenType::PrivateRistretto255
    }
}

/// Public key alias
pub type PublicKey<CS> = <<CS as CipherSuite>::Group as Group>::Elem;

/// Convert a public key to a token key ID.
pub fn public_key_to_truncated_token_key_id<CS: PrivateCipherSuite>(
    public_key: &<CS::Group as Group>::Elem,
) -> TruncatedTokenKeyId {
    truncate_token_key_id(&public_key_to_token_key_id::<CS>(public_key))
}

pub(crate) fn public_key_to_token_key_id<CS: PrivateCipherSuite>(
    public_key: &<CS::Group as Group>::Elem,
) -> TokenKeyId {
    let public_key = serialize_public_key::<CS>(*public_key);

    Sha256::digest(public_key).into()
}

/// Serializes a public key.
#[must_use]
pub fn serialize_public_key<CS: PrivateCipherSuite>(
    public_key: <CS::Group as Group>::Elem,
) -> Vec<u8> {
    <CS::Group as Group>::serialize_elem(public_key).to_vec()
}

/// Deserializes a public key from a slice of bytes.
///
/// # Errors
///
/// This function will return an error if the slice is not a valid public key.
pub fn deserialize_public_key<CS: PrivateCipherSuite>(
    slice: &[u8],
) -> Result<PublicKey<CS>, Error> {
    <CS::Group as Group>::deserialize_elem(slice)
}
