//! Common error types

use blind_rsa_signatures::Error as BlindRsaError;
use thiserror::Error;

use crate::{
    TokenType, auth::authenticate::SerializationError as TokenChallengeSerializationError,
};
use tls_codec::Error as TlsCodecError;
use voprf::Error as VoprfError;

/// Serialization error
#[derive(PartialEq, Eq, Error, Debug)]
pub enum SerializationError {
    #[error("Invalid serialized data")]
    /// Invalid serialized data
    InvalidData {
        /// Underlying TLS codec error that triggered the failure.
        #[source]
        source: TlsCodecError,
    },
}

/// Errors that can occur when creating a keypair.
#[derive(PartialEq, Eq, Error, Debug)]
pub enum CreateKeypairError {
    #[error("Seed is too long")]
    /// Error when the seed is too long.
    SeedError {
        /// Underlying VOPRF error that triggered the failure.
        #[source]
        source: VoprfError,
    },
    #[error("Key generation failed")]
    /// Error when generating an RSA keypair fails.
    KeyGenerationFailed {
        /// Underlying RSA error that triggered the failure.
        #[source]
        source: BlindRsaError,
    },
    #[error("Key serialization failed")]
    /// Error when serializing the public key fails.
    KeySerializationFailed {
        /// Underlying RSA error that triggered the failure.
        #[source]
        source: BlindRsaError,
    },
    #[error("Collision exhausted")]
    /// Error when collision attempts are exhausted
    CollisionExhausted,
}

/// Errors that can occur when issuing token requests.
#[derive(PartialEq, Eq, Error, Debug)]
pub enum IssueTokenRequestError {
    #[error("Token blinding error")]
    /// Error when blinding the token.
    BlindingError {
        /// Underlying blinding error that triggered the failure.
        #[source]
        source: BlindingErrorSource,
    },
    #[error("Invalid TokenChallenge")]
    /// Error when the token challenge is invalid.
    InvalidTokenChallenge {
        /// Underlying token challenge serialization error that triggered the failure.
        #[source]
        source: TokenChallengeSerializationError,
    },
}

/// Source errors for blinding failures.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum BlindingErrorSource {
    /// VOPRF-specific blinding error.
    #[error(transparent)]
    Voprf(#[from] VoprfError),
    /// RSA-specific blinding error.
    #[error(transparent)]
    Rsa(#[from] BlindRsaError),
}

/// Errors that can occur when issuing the token response.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum IssueTokenResponseError {
    #[error("Key ID not found")]
    /// Error when the key ID is not found.
    KeyIdNotFound,
    #[error("Invalid blinded message")]
    /// Error when deserializing the blinded message fails.
    InvalidBlindedMessage {
        /// Underlying VOPRF error that triggered the failure.
        #[source]
        source: VoprfError,
    },
    #[error("Blind evaluation failed")]
    /// Error when the server fails to evaluate the blinded elements.
    BlindEvaluationFailed {
        /// Underlying VOPRF error that triggered the failure.
        #[source]
        source: VoprfError,
    },
    #[error("Blind signature failed")]
    /// Error when the server fails to compute a blind signature.
    BlindSignatureFailed {
        /// Underlying RSA error that triggered the failure.
        #[source]
        source: BlindRsaError,
    },
    #[error("Invalid token type: expected {expected:?}, found {found:?}")]
    /// Error when the token type does not match the expected type.
    InvalidTokenType {
        /// Expected token type for the operation.
        expected: TokenType,
        /// Actual token type found in the request.
        found: TokenType,
    },
    #[error("Batch size {size} exceeds maximum {max}")]
    /// Error when the batch size exceeds the server's configured limit.
    BatchTooLarge {
        /// Maximum allowed batch size.
        max: usize,
        /// Actual batch size in the request.
        size: usize,
    },
}

/// Errors that can occur when issuing tokens.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum IssueTokenError {
    #[error("Invalid evaluation element for {token_type:?} token")]
    /// Error when the evaluation element cannot be deserialized.
    InvalidEvaluationElement {
        /// Token type for which deserialization failed.
        token_type: TokenType,
        /// Underlying VOPRF error that triggered the failure.
        #[source]
        source: VoprfError,
    },
    #[error("Invalid proof for {token_type:?} token")]
    /// Error when the proof cannot be deserialized.
    InvalidProof {
        /// Token type for which proof deserialization failed.
        token_type: TokenType,
        /// Underlying VOPRF error that triggered the failure.
        #[source]
        source: VoprfError,
    },
    #[error("Finalization failed for {token_type:?} token")]
    /// Error when finalizing a single token fails.
    FinalizationFailed {
        /// Token type for which finalization failed.
        token_type: TokenType,
        /// Underlying VOPRF error that triggered the failure.
        #[source]
        source: VoprfError,
    },
    #[error("Batch finalization failed for {token_type:?} token")]
    /// Error when finalizing a batch of tokens fails.
    BatchFinalizationFailed {
        /// Token type for which batch finalization failed.
        token_type: TokenType,
        /// Underlying VOPRF error that triggered the failure.
        #[source]
        source: VoprfError,
    },
    #[error("Unexpected token response type: expected {expected:?}, found {found:?}")]
    /// Error when a generic token response does not match the expected type.
    UnexpectedTokenResponseType {
        /// Expected token type inferred from the token state.
        expected: TokenType,
        /// Token type present in the response.
        found: TokenType,
    },
    #[error("Signature finalization failed for {token_type:?} token")]
    /// Error when finalizing a public token signature fails.
    SignatureFinalizationFailed {
        /// Token type for which signature finalization failed.
        token_type: TokenType,
        /// Underlying RSA error that triggered the failure.
        #[source]
        source: BlindRsaError,
    },
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
    #[error("Token type mismatch: expected {expected:?}, found {found:?}")]
    /// Error when the token type does not match the expected type.
    TokenTypeMismatch {
        /// Expected token type.
        expected: TokenType,
        /// Token type found in the token.
        found: TokenType,
    },
    #[error("Invalid authenticator length: expected {expected}, found {found}")]
    /// Error when the authenticator length does not match the expected size.
    InvalidAuthenticatorLength {
        /// Expected authenticator length.
        expected: usize,
        /// Actual authenticator length found in the token.
        found: usize,
    },
    #[error("Failed to derive authenticator for {token_type:?} token")]
    /// Error when deriving the expected authenticator fails.
    AuthenticatorDerivationFailed {
        /// Token type that was being redeemed.
        token_type: TokenType,
        /// Underlying VOPRF error that triggered the failure.
        #[source]
        source: VoprfError,
    },
    #[error("Authenticator mismatch for {token_type:?} token")]
    /// Error when the provided authenticator does not match the expected value.
    AuthenticatorMismatch {
        /// Token type that was being redeemed.
        token_type: TokenType,
    },
    #[error("Invalid {token_type:?} token signature")]
    /// Error when the public token signature verification fails.
    InvalidSignature {
        /// Token type that was being redeemed.
        token_type: TokenType,
    },
}
