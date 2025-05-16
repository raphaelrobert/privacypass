//! Store private token key material
use async_trait::async_trait;
use voprf::VoprfServer;

use crate::TruncatedTokenKeyId;

use super::private::PrivateCipherSuite;

/// Minimal trait for a key store to store key material on the server-side. Note
/// that the store requires inner mutability.
#[async_trait]
pub trait PrivateKeyStore {
    /// The cipher suite used for the key store.
    type CS: PrivateCipherSuite;
    /// Inserts a keypair with a given `truncated_token_key_id` into the key store.
    async fn insert(
        &self,
        truncated_token_key_id: TruncatedTokenKeyId,
        server: VoprfServer<Self::CS>,
    );
    /// Returns a keypair with a given `truncated_token_key_id` from the key store.
    async fn get(
        &self,
        truncated_token_key_id: &TruncatedTokenKeyId,
    ) -> Option<VoprfServer<Self::CS>>;
}
