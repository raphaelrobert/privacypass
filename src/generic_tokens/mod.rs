//! # Generic Tokens

#[cfg(feature = "p384")]
use p384::NistP384;
#[cfg(feature = "ristretto255")]
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
    #[cfg(feature = "p384")]
    PrivateP384(Box<crate::private_tokens::PrivateToken<NistP384>>),
    /// Public token
    #[cfg(feature = "rsa")]
    Public(Box<crate::public_tokens::PublicToken>),
    /// Private ristretto255 token
    #[cfg(feature = "ristretto255")]
    PrivateRistretto255(Box<crate::private_tokens::PrivateToken<Ristretto255>>),
}

impl GenericToken {
    /// Get the token type
    pub fn token_type(&self) -> TokenType {
        match self {
            #[cfg(feature = "p384")]
            GenericToken::PrivateP384(_) => TokenType::PrivateP384,
            #[cfg(feature = "rsa")]
            GenericToken::Public(_) => TokenType::Public,
            #[cfg(feature = "ristretto255")]
            GenericToken::PrivateRistretto255(_) => TokenType::PrivateRistretto255,
        }
    }

    /// Get the challenge
    pub fn challenge_digest(&self) -> &ChallengeDigest {
        match self {
            #[cfg(feature = "p384")]
            GenericToken::PrivateP384(token) => token.challenge_digest(),
            #[cfg(feature = "rsa")]
            GenericToken::Public(token) => token.challenge_digest(),
            #[cfg(feature = "ristretto255")]
            GenericToken::PrivateRistretto255(token) => token.challenge_digest(),
        }
    }
}

impl GenericToken {
    #[cfg(feature = "p384")]
    pub(crate) fn from_private_p384(tok: crate::private_tokens::PrivateToken<NistP384>) -> Self {
        GenericToken::PrivateP384(Box::new(tok))
    }
    #[cfg(feature = "rsa")]
    pub(crate) fn from_public(tok: crate::public_tokens::PublicToken) -> Self {
        GenericToken::Public(Box::new(tok))
    }
    #[cfg(feature = "ristretto255")]
    pub(crate) fn from_private_ristretto(
        tok: crate::private_tokens::PrivateToken<Ristretto255>,
    ) -> Self {
        GenericToken::PrivateRistretto255(Box::new(tok))
    }
}
