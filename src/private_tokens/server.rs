//! Server-side implementation of Privately Verifiable Token protocol.

use async_trait::async_trait;
use generic_array::ArrayLength;
use generic_array::GenericArray;
use p384::NistP384;
use rand::{rngs::OsRng, RngCore};
use thiserror::Error;
use voprf::{BlindedElement, Error, Group, Result, VoprfServer};

use crate::TokenInput;
use crate::{auth::authorize::Token, NonceStore, TokenKeyId, TokenType};

use super::key_id_to_token_key_id;
use super::public_key_to_key_id;
use super::PublicKey;
use super::NK;
use super::NS;
use super::{TokenRequest, TokenResponse};

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
pub trait KeyStore: Send + Sync {
    /// Inserts a keypair with a given `token_key_id` into the key store.
    async fn insert(&self, token_key_id: TokenKeyId, server: VoprfServer<NistP384>);
    /// Returns a keypair with a given `token_key_id` from the key store.
    async fn get(&self, token_key_id: &TokenKeyId) -> Option<VoprfServer<NistP384>>;
}

/// Serializes a public key.
#[must_use]
pub fn serialize_public_key(public_key: PublicKey) -> Vec<u8> {
    <NistP384 as Group>::serialize_elem(public_key).to_vec()
}

/// Deserializes a public key from a slice of bytes.
///
/// # Errors
///
/// This function will return an error if the slice is not a valid public key.
pub fn deserialize_public_key(slice: &[u8]) -> Result<PublicKey, Error> {
    <NistP384 as Group>::deserialize_elem(slice)
}

/// Server side implementation of Privately Verifiable Token protocol.
#[derive(Default, Debug)]
pub struct Server {
    rng: OsRng,
}

impl Server {
    /// Creates a new server.
    #[must_use]
    pub const fn new() -> Self {
        Self { rng: OsRng }
    }

    /// Creates a new keypair and inserts it into the key store.
    ///
    /// # Errors
    /// Returns an error if creating the keypair failed.
    pub async fn create_keypair<KS: KeyStore>(
        &mut self,
        key_store: &KS,
    ) -> Result<PublicKey, CreateKeypairError> {
        let mut seed = GenericArray::<_, <NistP384 as Group>::ScalarLen>::default();
        self.rng.fill_bytes(&mut seed);
        let server = VoprfServer::<NistP384>::new_from_seed(&seed, b"PrivacyPass")
            .map_err(|_| CreateKeypairError::SeedError)?;
        let public_key = server.get_public_key();
        let token_key_id = key_id_to_token_key_id(&public_key_to_key_id(&server.get_public_key()));
        key_store.insert(token_key_id, server).await;
        Ok(public_key)
    }

    /// Issues a token response.
    ///
    /// # Errors
    /// Returns an error if the token request is invalid.
    pub async fn issue_token_response<KS: KeyStore>(
        &mut self,
        key_store: &KS,
        token_request: TokenRequest,
    ) -> Result<TokenResponse, IssueTokenResponseError> {
        if token_request.token_type != TokenType::Private {
            return Err(IssueTokenResponseError::InvalidTokenType);
        }
        let server = key_store
            .get(&token_request.token_key_id)
            .await
            .ok_or(IssueTokenResponseError::KeyIdNotFound)?;
        let blinded_element = BlindedElement::<NistP384>::deserialize(&token_request.blinded_msg)
            .map_err(|_| IssueTokenResponseError::InvalidTokenRequest)?;
        let evaluated_result = server.blind_evaluate(&mut self.rng, &blinded_element);
        let mut evaluate_proof = [0u8; NS + NS];
        evaluate_proof[..(NS + NS)].copy_from_slice(&evaluated_result.proof.serialize());
        Ok(TokenResponse {
            evaluate_msg: evaluated_result.message.serialize().into(),
            evaluate_proof,
        })
    }

    /// Redeems a token.
    ///
    /// # Errors
    /// Returns an error if the token is invalid.
    pub async fn redeem_token<KS: KeyStore, NS: NonceStore, Nk: ArrayLength<u8>>(
        &mut self,
        key_store: &KS,
        nonce_store: &NS,
        token: Token<Nk>,
    ) -> Result<(), RedeemTokenError> {
        if token.token_type() != TokenType::Private {
            return Err(RedeemTokenError::InvalidToken);
        }
        if token.authenticator().len() != NK {
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

        let server = key_store
            .get(&key_id_to_token_key_id(token.token_key_id()))
            .await
            .ok_or(RedeemTokenError::KeyIdNotFound)?;
        let token_authenticator = server
            .evaluate(&token_input.serialize())
            .map_err(|_| RedeemTokenError::InvalidToken)?
            .to_vec();
        if token.authenticator() == token_authenticator {
            nonce_store.insert(token.nonce()).await;
            Ok(())
        } else {
            Err(RedeemTokenError::InvalidToken)
        }
    }

    /// Sets a keypair with a given `private_key` into the key store.
    #[cfg(feature = "kat")]
    pub async fn set_key<KS: KeyStore>(
        &mut self,
        key_store: &KS,
        private_key: &[u8],
    ) -> Result<PublicKey, CreateKeypairError> {
        let server = VoprfServer::<NistP384>::new_with_key(private_key)
            .map_err(|_| CreateKeypairError::SeedError)?;
        let public_key = server.get_public_key();
        let token_key_id = key_id_to_token_key_id(&public_key_to_key_id(&server.get_public_key()));
        key_store.insert(token_key_id, server).await;
        Ok(public_key)
    }
}
