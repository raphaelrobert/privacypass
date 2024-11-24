//! Server-side implementation of Publicly Verifiable Token protocol.

use async_trait::async_trait;
use blind_rsa_signatures::{KeyPair, Options, PublicKey, Signature};
use generic_array::ArrayLength;
use rand::{rngs::OsRng, CryptoRng, RngCore};
use thiserror::Error;

use crate::{auth::authorize::Token, NonceStore, TokenInput, TokenType, TruncatedTokenKeyId};

use super::{public_key_to_token_key_id, truncate_token_key_id, TokenRequest, TokenResponse, NK};

/// Errors that can occur when creating a keypair.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum CreateKeypairError {
    #[error("Seed is too long")]
    /// Error when the seed is too long.
    SeedError,
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

/// Minimal trait for a key store to store key material on the server-side. Note
/// that the store requires inner mutability.
#[async_trait]

pub trait IssuerKeyStore: Send + Sync {
    /// Inserts a keypair with a given `truncated_token_key_id` into the key store.
    async fn insert(&self, truncated_token_key_id: TruncatedTokenKeyId, server: KeyPair);
    /// Returns a keypair with a given `truncated_token_key_id` from the key store.
    async fn get(&self, truncated_token_key_id: &TruncatedTokenKeyId) -> Option<KeyPair>;
}

/// Minimal trait for a key store to store key material on the server-side. Note
/// that the store requires inner mutability.
#[async_trait]
pub trait OriginKeyStore {
    /// Inserts a keypair with a given `truncated_token_key_id` into the key store.
    async fn insert(&self, truncated_token_key_id: TruncatedTokenKeyId, server: PublicKey);
    /// Returns a keypair with a given `truncated_token_key_id` from the key store.
    async fn get(&self, truncated_token_key_id: &TruncatedTokenKeyId) -> Option<PublicKey>;
}

/// Serializes a keypair into a DER-encoded PKCS#8 document.
#[must_use]
pub fn serialize_public_key(public_key: &PublicKey) -> Vec<u8> {
    public_key.to_spki(Some(&Options::default())).unwrap()
}

const KEYSIZE_IN_BITS: usize = 2048;
const KEYSIZE_IN_BYTES: usize = KEYSIZE_IN_BITS / 8;

/// Server-side implementation of Publicly Verifiable Token protocol for
/// issuers.
#[derive(Default, Debug)]
pub struct IssuerServer {}

impl IssuerServer {
    /// Creates a new server.
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }

    /// Creates a new keypair and inserts it into the key store.
    ///
    /// # Errors
    /// Returns an error if creating the keypair fails.
    pub async fn create_keypair<IKS: IssuerKeyStore, R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        key_store: &IKS,
    ) -> Result<KeyPair, CreateKeypairError> {
        let key_pair =
            KeyPair::generate(rng, KEYSIZE_IN_BITS).map_err(|_| CreateKeypairError::SeedError)?;
        let truncated_token_key_id =
            truncate_token_key_id(&public_key_to_token_key_id(&key_pair.pk));
        key_store
            .insert(truncated_token_key_id, key_pair.clone())
            .await;
        Ok(key_pair)
    }

    /// Issues a new token response.
    ///
    /// # Errors
    /// Returns an error if the token request is invalid.
    pub async fn issue_token_response<IKS: IssuerKeyStore>(
        &self,
        key_store: &IKS,
        token_request: TokenRequest,
    ) -> Result<TokenResponse, IssueTokenResponseError> {
        let rng = &mut OsRng;
        if token_request.token_type != TokenType::PublicToken {
            return Err(IssueTokenResponseError::InvalidTokenType);
        }
        let key_pair = key_store
            .get(&token_request.truncated_token_key_id)
            .await
            .ok_or(IssueTokenResponseError::KeyIdNotFound)?;

        // blind_sig = rsabssa_blind_sign(skI, TokenRequest.blinded_msg)
        let options = Options::default();
        let blind_signature = key_pair
            .sk
            .blind_sign(rng, token_request.blinded_msg, &options)
            .map_err(|_| IssueTokenResponseError::InvalidTokenRequest)?;

        debug_assert!(blind_signature.len() == NK);
        let mut blind_sig = [0u8; NK];
        blind_sig.copy_from_slice(blind_signature.as_slice());

        Ok(TokenResponse { blind_sig })
    }

    /// Sets the given keypair.
    #[cfg(feature = "kat")]
    pub async fn set_keypair<IKS: IssuerKeyStore>(&self, key_store: &IKS, key_pair: KeyPair) {
        let truncated_token_key_id =
            truncate_token_key_id(&public_key_to_token_key_id(&key_pair.pk));
        key_store.insert(truncated_token_key_id, key_pair).await;
    }
}

/// Server-side implementation of Publicly Verifiable Token protocol for
/// origins.
#[derive(Default, Debug)]
pub struct OriginServer {}

impl OriginServer {
    /// Creates a new server.
    pub fn new() -> Self {
        Self {}
    }

    /// Redeems a token.
    ///
    /// # Errors
    /// Returns an error if the token is invalid.
    pub async fn redeem_token<OKS: OriginKeyStore, NS: NonceStore, Nk: ArrayLength<u8>>(
        &self,
        key_store: &OKS,
        nonce_store: &NS,
        token: Token<Nk>,
    ) -> Result<(), RedeemTokenError> {
        if token.token_type() != TokenType::PublicToken {
            return Err(RedeemTokenError::InvalidToken);
        }
        if token.authenticator().len() != KEYSIZE_IN_BYTES {
            return Err(RedeemTokenError::InvalidToken);
        }
        if nonce_store.exists(&token.nonce()).await {
            return Err(RedeemTokenError::DoubleSpending);
        }
        let token_input = TokenInput::new(
            token.token_type(),
            token.nonce(),
            *token.challenge_digest(),
            *token.token_key_id(),
        );

        let public_key = key_store
            .get(&truncate_token_key_id(token.token_key_id()))
            .await
            .ok_or(RedeemTokenError::KeyIdNotFound)?;

        let options = Options::default();
        let signature = Signature(token.authenticator().to_vec());

        signature
            .verify(&public_key, None, token_input.serialize(), &options)
            .map_err(|_| RedeemTokenError::InvalidToken)?;
        nonce_store.insert(token.nonce()).await;
        Ok(())
    }
}
