pub mod auth;
pub mod batched_tokens;
pub mod private_tokens;
pub mod public_tokens;

use async_trait::async_trait;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

pub use tls_codec::{Deserialize, Serialize};

#[derive(TlsSize, TlsSerialize, TlsDeserialize, Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum TokenType {
    Private = 1,
    Public = 2,
    Batched = 0xF91A,
}

pub type TokenKeyId = u8;
pub type KeyId = [u8; 32];
pub type Nonce = [u8; 32];
pub type ChallengeDigest = [u8; 32];

#[async_trait]
pub trait NonceStore {
    /// Returns `true` if the nonce exists in the nonce store and `false` otherwise.
    async fn exists(&self, nonce: &Nonce) -> bool;
    /// Inserts a new nonce in the nonce store.
    async fn insert(&self, nonce: Nonce);
}

pub(crate) struct TokenInput {
    token_type: TokenType,
    nonce: Nonce,
    challenge_digest: ChallengeDigest,
    key_id: KeyId,
}

impl TokenInput {
    pub fn new(
        token_type: TokenType,
        nonce: Nonce,
        challenge_digest: ChallengeDigest,
        key_id: KeyId,
    ) -> Self {
        Self {
            token_type,
            nonce,
            challenge_digest,
            key_id,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        // token_input = concat(0xXXXX, nonce, challenge_digest, token_key_id)
        let mut token_input: Vec<u8> = Vec::new();
        token_input.extend_from_slice((self.token_type as u16).to_be_bytes().as_slice());
        token_input.extend_from_slice(self.nonce.as_slice());
        token_input.extend_from_slice(self.challenge_digest.as_slice());
        token_input.extend_from_slice(self.key_id.as_slice());
        token_input
    }
}
