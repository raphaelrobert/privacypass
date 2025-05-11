//! Common error types

use thiserror::Error;

/// Serialization error
#[derive(Error, Debug)]
pub enum SerializationError {
    #[error("Invalid serialized data")]
    /// Invalid serialized data
    InvalidData,
}

/// Errors that can occur when creating a keypair.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum CreateKeypairError {
    #[error("Seed is too long")]
    /// Error when the seed is too long.
    SeedError,
}

/// Errors that can occur when issuing token requests.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum IssueTokenRequestError {
    #[error("Token blinding error")]
    /// Error when blinding the token.
    BlindingError,
    #[error("Invalid TokenChallenge")]
    /// Error when the token challenge is invalid.
    InvalidTokenChallenge,
}

/// Errors that can occur when issuing the token response.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum IssueTokenResponseError {
    #[error("Key ID not found")]
    /// Error when the key ID is not found.
    KeyIdNotFound,
    #[error("Invalid TokenRequest")]
    /// Error when the token request is invalid.
    InvalidTokenRequest,
    #[error("Invalid toke type")]
    /// Error when the token type is invalid.
    InvalidTokenType,
}

/// Errors that can occur when issuing tokens.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum IssueTokenError {
    #[error("Invalid TokenResponse")]
    /// Error when the token response is invalid.
    InvalidTokenResponse,
}

/// Errors that can occur when redeeming the token.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum RedeemTokenError {
    #[error("Key ID not found")]
    /// Error when the key ID is not found.
    KeyIdNotFound,
    #[error("The token has already been redeemed")]
    /// Error when the token has already been redeemed.
    DoubleSpending,
    #[error("The token is invalid")]
    /// Error when the token is invalid.
    InvalidToken,
}
