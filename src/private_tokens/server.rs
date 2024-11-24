//! Server-side implementation of Privately Verifiable Token protocol.

use async_trait::async_trait;
use generic_array::ArrayLength;
use generic_array::GenericArray;
use p384::NistP384;
use rand::{rngs::OsRng, RngCore};
use thiserror::Error;
use voprf::{BlindedElement, Error, Group, Result, VoprfServer};

use crate::{auth::authorize::Token, NonceStore, TokenInput, TokenType, TruncatedTokenKeyId};

use super::{
    public_key_to_token_key_id, truncate_token_key_id, PublicKey, TokenRequest, TokenResponse, NK,
    NS,
};

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
pub trait PrivateKeyStore: Send + Sync {
    /// Inserts a keypair with a given `truncated_token_key_id` into the key store.
    async fn insert(
        &self,
        truncated_token_key_id: TruncatedTokenKeyId,
        server: VoprfServer<NistP384>,
    );
    /// Returns a keypair with a given `truncated_token_key_id` from the key store.
    async fn get(
        &self,
        truncated_token_key_id: &TruncatedTokenKeyId,
    ) -> Option<VoprfServer<NistP384>>;
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
pub struct Server {}

impl Server {
    /// Creates a new server.
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }

    /// Creates a new keypair and inserts it into the key store.
    ///
    /// # Errors
    /// Returns an error if creating the keypair failed.
    pub async fn create_keypair<PKS: PrivateKeyStore>(
        &self,
        key_store: &PKS,
    ) -> Result<PublicKey, CreateKeypairError> {
        let mut seed = GenericArray::<_, <NistP384 as Group>::ScalarLen>::default();
        OsRng.fill_bytes(&mut seed);
        self.create_keypair_internal(key_store, &seed, b"PrivacyPass")
            .await
    }

    /// Creates a new keypair and inserts it into the key store.
    async fn create_keypair_internal<PKS: PrivateKeyStore>(
        &self,
        key_store: &PKS,
        seed: &[u8],
        info: &[u8],
    ) -> Result<PublicKey, CreateKeypairError> {
        let server = VoprfServer::<NistP384>::new_from_seed(seed, info)
            .map_err(|_| CreateKeypairError::SeedError)?;
        let public_key = server.get_public_key();
        let truncated_token_key_id =
            truncate_token_key_id(&public_key_to_token_key_id(&server.get_public_key()));
        key_store.insert(truncated_token_key_id, server).await;
        Ok(public_key)
    }

    /// Creates a new keypair with explicit parameters and inserts it into the
    /// key store.
    #[cfg(feature = "kat")]
    pub async fn create_keypair_with_params<PKS: PrivateKeyStore>(
        &self,
        key_store: &PKS,
        seed: &[u8],
        info: &[u8],
    ) -> Result<PublicKey, CreateKeypairError> {
        self.create_keypair_internal(key_store, seed, info).await
    }

    /// Issues a token response.
    ///
    /// # Errors
    /// Returns an error if the token request is invalid.
    pub async fn issue_token_response<PKS: PrivateKeyStore>(
        &self,
        key_store: &PKS,
        token_request: TokenRequest,
    ) -> Result<TokenResponse, IssueTokenResponseError> {
        if token_request.token_type != TokenType::PrivateToken {
            return Err(IssueTokenResponseError::InvalidTokenType);
        }
        let server = key_store
            .get(&token_request.truncated_token_key_id)
            .await
            .ok_or(IssueTokenResponseError::KeyIdNotFound)?;
        let blinded_element = BlindedElement::<NistP384>::deserialize(&token_request.blinded_msg)
            .map_err(|_| IssueTokenResponseError::InvalidTokenRequest)?;
        let evaluated_result = server.blind_evaluate(&mut OsRng, &blinded_element);
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
    pub async fn redeem_token<PKS: PrivateKeyStore, NS: NonceStore, Nk: ArrayLength<u8>>(
        &self,
        key_store: &PKS,
        nonce_store: &NS,
        token: Token<Nk>,
    ) -> Result<(), RedeemTokenError> {
        if token.token_type() != TokenType::PrivateToken {
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
            .get(&truncate_token_key_id(token.token_key_id()))
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
    pub async fn set_key<PKS: PrivateKeyStore>(
        &self,
        key_store: &PKS,
        private_key: &[u8],
    ) -> Result<PublicKey, CreateKeypairError> {
        let server = VoprfServer::<NistP384>::new_with_key(private_key)
            .map_err(|_| CreateKeypairError::SeedError)?;
        let public_key = server.get_public_key();
        let truncated_token_key_id =
            truncate_token_key_id(&public_key_to_token_key_id(&server.get_public_key()));
        key_store.insert(truncated_token_key_id, server).await;
        Ok(public_key)
    }
}
