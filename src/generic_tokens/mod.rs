//! # Generic Tokens

use p384::NistP384;
use voprf::Ristretto255;

use crate::{ChallengeDigest, TokenType};

pub mod request;
pub mod response;
pub mod server;

pub use request::*;
pub use response::*;

/// Generic token
#[derive(Debug)]
pub enum GenericToken {
    /// Private p384 token
    PrivateP384(Box<crate::private_tokens::PrivateToken<NistP384>>),
    /// Public token
    Public(Box<crate::public_tokens::PublicToken>),
    /// Private ristretto255 token
    PrivateRistretto255(Box<crate::private_tokens::PrivateToken<Ristretto255>>),
}

impl GenericToken {
    /// Get the token type
    pub fn token_type(&self) -> TokenType {
        match self {
            GenericToken::PrivateP384(_) => TokenType::PrivateP384,
            GenericToken::Public(_) => TokenType::Public,
            GenericToken::PrivateRistretto255(_) => TokenType::PrivateRistretto255,
        }
    }

    /// Get the challenge
    pub fn challenge_digest(&self) -> &ChallengeDigest {
        match self {
            GenericToken::PrivateP384(token) => token.challenge_digest(),
            GenericToken::Public(token) => token.challenge_digest(),
            GenericToken::PrivateRistretto255(token) => token.challenge_digest(),
        }
    }
}

impl GenericToken {
    pub(crate) fn from_private_p384(tok: crate::private_tokens::PrivateToken<NistP384>) -> Self {
        GenericToken::PrivateP384(Box::new(tok))
    }
    pub(crate) fn from_public(tok: crate::public_tokens::PublicToken) -> Self {
        GenericToken::Public(Box::new(tok))
    }
    pub(crate) fn from_private_ristretto(
        tok: crate::private_tokens::PrivateToken<Ristretto255>,
    ) -> Self {
        GenericToken::PrivateRistretto255(Box::new(tok))
    }
}
