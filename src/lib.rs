//! # Privacy Pass
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
//!  - Amortized Tokens
//!  - Generic Tokens

#![warn(missing_docs)]
#![deny(unreachable_pub)]
#![deny(missing_debug_implementations)]
#![deny(unsafe_code)]

pub mod amortized_tokens;
pub mod auth;
pub mod common;
pub mod generic_tokens;
pub mod private_tokens;
pub mod public_tokens;
#[cfg(feature = "test-utils")]
pub mod test_utils;

use async_trait::async_trait;
use std::fmt::Debug;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

pub use tls_codec::{Deserialize, Serialize};
pub use voprf::{Group, VoprfServer};

/// Token type
#[derive(TlsSize, TlsSerialize, TlsDeserialize, Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum TokenType {
    /// Private p384 token
    PrivateP384 = 1,
    /// Public token
    Public = 2,
    /// Private ristretto255 token
    PrivateRistretto255 = 5,
}

/// Token key ID
pub type TruncatedTokenKeyId = u8;
/// Key ID
pub type TokenKeyId = [u8; 32];
/// Nonce
pub type Nonce = [u8; 32];
/// Challenge digest
pub type ChallengeDigest = [u8; 32];

pub(crate) fn truncate_token_key_id(token_key_id: &TokenKeyId) -> TruncatedTokenKeyId {
    *token_key_id.iter().last().unwrap_or(&0)
}

/// Nonce store for tracking redeemed tokens and preventing double spending.
///
/// Implements a three-state machine: **absent → reserved → committed**, with
/// **reserved → absent** via [`release`](NonceStore::release).
///
/// # Security contract
///
/// - [`reserve`](NonceStore::reserve) is atomic: exactly one concurrent caller
///   wins the race, preventing TOCTOU double-spending.
/// - [`release`](NonceStore::release) releases a reservation when cryptographic
///   verification fails, preventing nonce-burning attacks.
/// - [`commit`](NonceStore::commit) finalizes a nonce after successful
///   cryptographic verification.
///
/// # Stale reservations
///
/// A crash between [`reserve`](NonceStore::reserve) and
/// [`commit`](NonceStore::commit)/[`release`](NonceStore::release) leaves a
/// nonce in the reserved state. Production implementations should apply a TTL
/// to reserved entries so they expire automatically.
///
/// The store requires interior mutability.
#[async_trait]
pub trait NonceStore: Send + Sync {
    /// Atomically transitions a nonce from absent to reserved.
    ///
    /// Returns `true` if newly reserved, `false` if already reserved
    /// or committed (replay / concurrent duplicate).
    async fn reserve(&self, nonce: &Nonce) -> bool;

    /// Transitions a nonce from reserved to committed.
    ///
    /// Called after cryptographic verification succeeds. Only reserved nonces
    /// can be committed; absent or already committed nonces are no-ops.
    async fn commit(&self, nonce: &Nonce);

    /// Transitions a nonce from reserved back to absent.
    ///
    /// Called when cryptographic verification fails, releasing the reservation
    /// so the nonce is not permanently burned. Only reserved nonces can be
    /// released; committed or absent nonces are no-ops.
    async fn release(&self, nonce: &Nonce);
}

#[derive(Debug)]
pub(crate) struct TokenInput {
    token_type: TokenType,
    nonce: Nonce,
    challenge_digest: ChallengeDigest,
    token_key_id: TokenKeyId,
}

impl TokenInput {
    pub(crate) const fn new(
        token_type: TokenType,
        nonce: Nonce,
        challenge_digest: ChallengeDigest,
        token_key_id: TokenKeyId,
    ) -> Self {
        Self {
            token_type,
            nonce,
            challenge_digest,
            token_key_id,
        }
    }

    pub(crate) fn serialize(&self) -> Vec<u8> {
        // token_input = concat(0xXXXX, nonce, challenge_digest, token_key_id)
        let mut token_input: Vec<u8> = Vec::new();
        token_input.extend_from_slice((self.token_type as u16).to_be_bytes().as_slice());
        token_input.extend_from_slice(self.nonce.as_slice());
        token_input.extend_from_slice(self.challenge_digest.as_slice());
        token_input.extend_from_slice(self.token_key_id.as_slice());
        token_input
    }
}

pub(crate) const COLLISION_AVOIDANCE_ATTEMPTS: usize = 100;
