//! Privacy Pass
//!
//! A Rust implementation of the Privacy Pass protocol as specified in Privacy
//! Pass IETF WG
//! [documents](https://datatracker.ietf.org/wg/privacypass/documents/).
//!
//! The library implements both the server side and the client side components
//! for the following token types:
//!
//!  - Privately Verfifiable Tokens
//!  - Publicly Verfifiable Tokens
//!  - Batched Tokens
//!

#![warn(missing_docs)]
#![deny(unreachable_pub)]
#![deny(missing_debug_implementations)]
#![deny(unsafe_code)]

pub mod auth;
pub mod batched_tokens;
pub mod private_tokens;
pub mod public_tokens;

use async_trait::async_trait;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

pub use tls_codec::{Deserialize, Serialize};

/// Token type
#[derive(TlsSize, TlsSerialize, TlsDeserialize, Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum TokenType {
    /// Privately verifiable token
    Private = 1,
    /// Publicly verifiable token
    Public = 2,
    /// Batched token
    Batched = 0xF91A,
}

/// Token key ID
pub type TokenKeyId = u8;
/// Key ID
pub type KeyId = [u8; 32];
/// Nonce
pub type Nonce = [u8; 32];
/// Challenge digest
pub type ChallengeDigest = [u8; 32];

/// Minimal trait for a nonce store that can be used to track redeemed tokens
/// and prevent double spending. Note that the store requires inner mutability.
#[async_trait]
pub trait NonceStore: Send + Sync {
    /// Returns `true` if the nonce exists in the nonce store and `false` otherwise.
    async fn exists(&self, nonce: &Nonce) -> bool;
    /// Inserts a new nonce in the nonce store.
    async fn insert(&self, nonce: Nonce);
}

#[derive(Debug)]
pub(crate) struct TokenInput {
    token_type: TokenType,
    nonce: Nonce,
    challenge_digest: ChallengeDigest,
    key_id: KeyId,
}

impl TokenInput {
    pub(crate) const fn new(
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

    pub(crate) fn serialize(&self) -> Vec<u8> {
        // token_input = concat(0xXXXX, nonce, challenge_digest, token_key_id)
        let mut token_input: Vec<u8> = Vec::new();
        token_input.extend_from_slice((self.token_type as u16).to_be_bytes().as_slice());
        token_input.extend_from_slice(self.nonce.as_slice());
        token_input.extend_from_slice(self.challenge_digest.as_slice());
        token_input.extend_from_slice(self.key_id.as_slice());
        token_input
    }
}
