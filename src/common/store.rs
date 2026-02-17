//! Store private token key material
use async_trait::async_trait;
use voprf::VoprfServer;

use crate::TruncatedTokenKeyId;

use super::private::PrivateCipherSuite;

/// Key store for VOPRF server keys (private and amortized tokens).
///
/// The store requires interior mutability.
///
/// # Truncated key ID collision space
///
/// RFC 9578 mandates a single-byte `truncated_token_key_id` (256 possible
/// values). By the birthday bound, collision probability exceeds 50% at
/// ~20 active keys. Key creation retries up to
/// [`COLLISION_AVOIDANCE_ATTEMPTS`](crate::COLLISION_AVOIDANCE_ATTEMPTS)
/// times, but the space is inherently small. Use [`remove`](Self::remove)
/// to reclaim slots when rotating keys.
///
/// # Zeroization
///
/// [`VoprfServer<CS>`] implements `ZeroizeOnDrop`, so key material stored
/// via this trait is automatically zeroized when the server value is dropped.
/// Implementors do not need to zeroize VOPRF keys manually.
#[async_trait]
pub trait PrivateKeyStore {
    /// The cipher suite used for the key store.
    type CS: PrivateCipherSuite;
    /// Inserts a keypair with a given `truncated_token_key_id` into the key
    /// store, only if it does not collide with an existing
    /// `truncated_token_key_id`.
    ///
    /// Returns `true` if the key was inserted, `false` if a collision occurred.
    async fn insert(
        &self,
        truncated_token_key_id: TruncatedTokenKeyId,
        server: VoprfServer<Self::CS>,
    ) -> bool;
    /// Returns a keypair with a given `truncated_token_key_id` from the key
    /// store.
    async fn get(
        &self,
        truncated_token_key_id: &TruncatedTokenKeyId,
    ) -> Option<VoprfServer<Self::CS>>;
    /// Removes a keypair by its `truncated_token_key_id`, reclaiming the
    /// slot for future key creation.
    ///
    /// Returns `true` if a key was removed, `false` if the ID was not found.
    async fn remove(&self, truncated_token_key_id: &TruncatedTokenKeyId) -> bool;
}
