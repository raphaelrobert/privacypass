//! Types that used by private tokens

use sha2::{Digest, Sha256};
use voprf::{CipherSuite, Error, Group};

use crate::{PPCipherSuite, TokenKeyId, TruncatedTokenKeyId, truncate_token_key_id};

/// Public key alias
pub type PublicKey<CS> = <<CS as CipherSuite>::Group as Group>::Elem;

/// Convert a public key to a token key ID.
pub fn public_key_to_truncated_token_key_id<CS: PPCipherSuite>(
    public_key: &<CS::Group as Group>::Elem,
) -> TruncatedTokenKeyId {
    truncate_token_key_id(&public_key_to_token_key_id::<CS>(public_key))
}

pub(crate) fn public_key_to_token_key_id<CS: PPCipherSuite>(
    public_key: &<CS::Group as Group>::Elem,
) -> TokenKeyId {
    let public_key = serialize_public_key::<CS>(*public_key);

    Sha256::digest(public_key).into()
}

/// Serializes a public key.
#[must_use]
pub fn serialize_public_key<CS: PPCipherSuite>(public_key: <CS::Group as Group>::Elem) -> Vec<u8> {
    <CS::Group as Group>::serialize_elem(public_key).to_vec()
}

/// Deserializes a public key from a slice of bytes.
///
/// # Errors
///
/// This function will return an error if the slice is not a valid public key.
pub fn deserialize_public_key<CS: PPCipherSuite>(slice: &[u8]) -> Result<PublicKey<CS>, Error> {
    <CS::Group as Group>::deserialize_elem(slice)
}
