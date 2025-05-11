//! # Arbitrary Batched Tokens

use p384::NistP384;
use voprf::Ristretto255;

use crate::{ChallengeDigest, TokenType};

pub mod request;
pub mod response;
pub mod server;

pub use request::*;
pub use response::*;

/// Arbitrary token
#[derive(Debug)]
pub enum ArbitraryBatchToken {
    /// Private p384 token
    PrivateP384(Box<crate::private_tokens::PrivateToken<NistP384>>),
    /// Public token
    Public(Box<crate::public_tokens::PublicToken>),
    /// Private ristretto255 token
    PrivateRistretto255(Box<crate::private_tokens::PrivateToken<Ristretto255>>),
}

impl ArbitraryBatchToken {
    /// Get the token type
    pub fn token_type(&self) -> TokenType {
        match self {
            ArbitraryBatchToken::PrivateP384(_) => TokenType::PrivateP384,
            ArbitraryBatchToken::Public(_) => TokenType::Public,
            ArbitraryBatchToken::PrivateRistretto255(_) => TokenType::PrivateRistretto255,
        }
    }

    /// Get the challenge
    pub fn challenge_digest(&self) -> &ChallengeDigest {
        match self {
            ArbitraryBatchToken::PrivateP384(token) => token.challenge_digest(),
            ArbitraryBatchToken::Public(token) => token.challenge_digest(),
            ArbitraryBatchToken::PrivateRistretto255(token) => token.challenge_digest(),
        }
    }
}

impl ArbitraryBatchToken {
    pub(crate) fn from_private_p384(tok: crate::private_tokens::PrivateToken<NistP384>) -> Self {
        ArbitraryBatchToken::PrivateP384(Box::new(tok))
    }
    pub(crate) fn from_public(tok: crate::public_tokens::PublicToken) -> Self {
        ArbitraryBatchToken::Public(Box::new(tok))
    }
    pub(crate) fn from_private_ristretto(
        tok: crate::private_tokens::PrivateToken<Ristretto255>,
    ) -> Self {
        ArbitraryBatchToken::PrivateRistretto255(Box::new(tok))
    }
}
