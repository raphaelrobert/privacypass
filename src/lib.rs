pub mod auth;
pub mod batched_tokens;
pub mod private_tokens;
pub mod public_tokens;

use async_trait::async_trait;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(TlsSize, TlsSerialize, TlsDeserialize, Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum TokenType {
    Private = 1,
    Public = 2,
    Batched = 3,
}

pub type KeyId = u8;
pub type Nonce = [u8; 32];
pub type ChallengeDigest = [u8; 32];

#[async_trait]
pub trait NonceStore {
    /// Returns `true` if the nonce exists in the nonce store and `false` otherwise.
    async fn exists(&self, nonce: &Nonce) -> bool;
    /// Inserts a new nonce in the nonce store.
    async fn insert(&mut self, nonce: Nonce);
}
