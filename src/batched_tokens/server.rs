//! Server-side implementation of the Batched Tokens protocol.

use async_trait::async_trait;
use generic_array::GenericArray;
use rand::{rngs::OsRng, RngCore};
use thiserror::Error;
use voprf::{
    BlindedElement, Error, Group, Result, Ristretto255, VoprfServer,
    VoprfServerBatchEvaluateFinishResult,
};

use crate::{batched_tokens::EvaluatedElement, NonceStore, TokenInput, TokenKeyId, TokenType};

use super::{
    key_id_to_token_key_id, public_key_to_key_id, BatchedToken, PublicKey, TokenRequest,
    TokenResponse, NK,
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
pub trait BatchedKeyStore: Send + Sync {
    /// Inserts a keypair with a given `token_key_id` into the key store.
    async fn insert(&self, token_key_id: TokenKeyId, server: VoprfServer<Ristretto255>);
    /// Returns a keypair with a given `token_key_id` from the key store.
    async fn get(&self, token_key_id: &TokenKeyId) -> Option<VoprfServer<Ristretto255>>;
}

/// Serializes a public key.
#[must_use]
pub fn serialize_public_key(public_key: PublicKey) -> Vec<u8> {
    <Ristretto255 as Group>::serialize_elem(public_key).to_vec()
}

/// Deserializes a public key from a slice of bytes.
///
/// # Errors
/// Returns an error if the slice is not a valid public key.
pub fn deserialize_public_key(slice: &[u8]) -> Result<PublicKey, Error> {
    <Ristretto255 as Group>::deserialize_elem(slice)
}

/// Server-side component of the batched token issuance protocol.
#[derive(Default, Debug)]
pub struct Server {}

impl Server {
    /// Create a new server. The new server does not contain any key material.
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }

    /// Creates a new keypair and inserts it into the key store.
    ///
    /// # Errors
    /// Returns an error if the seed is too long.
    pub async fn create_keypair<BKS: BatchedKeyStore>(
        &self,
        key_store: &BKS,
    ) -> Result<PublicKey, CreateKeypairError> {
        let mut seed = GenericArray::<_, <Ristretto255 as Group>::ScalarLen>::default();
        OsRng.fill_bytes(&mut seed);
        self.create_keypair_internal(key_store, &seed, b"PrivacyPass")
            .await
    }

    /// Creates a new keypair and inserts it into the key store.
    async fn create_keypair_internal<BKS: BatchedKeyStore>(
        &self,
        key_store: &BKS,
        seed: &[u8],
        info: &[u8],
    ) -> Result<PublicKey, CreateKeypairError> {
        let server = VoprfServer::<Ristretto255>::new_from_seed(seed, info)
            .map_err(|_| CreateKeypairError::SeedError)?;
        let public_key = server.get_public_key();
        let token_key_id = key_id_to_token_key_id(&public_key_to_key_id(&server.get_public_key()));
        key_store.insert(token_key_id, server).await;
        Ok(public_key)
    }

    /// Creates a new keypair with explicit parameters and inserts it into the
    /// key store.
    #[cfg(feature = "kat")]
    pub async fn create_keypair_with_params<BKS: BatchedKeyStore>(
        &self,
        key_store: &BKS,
        seed: &[u8],
        info: &[u8],
    ) -> Result<PublicKey, CreateKeypairError> {
        self.create_keypair_internal(key_store, seed, info).await
    }

    /// Issues a token response.
    ///
    /// # Errors
    /// Returns an error if the token request is invalid.
    pub async fn issue_token_response<BKS: BatchedKeyStore>(
        &self,
        key_store: &BKS,
        token_request: TokenRequest,
    ) -> Result<TokenResponse, IssueTokenResponseError> {
        if token_request.token_type != TokenType::Batched {
            return Err(IssueTokenResponseError::InvalidTokenType);
        }
        let server = key_store
            .get(&token_request.token_key_id)
            .await
            .ok_or(IssueTokenResponseError::KeyIdNotFound)?;

        let mut blinded_elements = Vec::new();
        for element in token_request.blinded_elements.iter() {
            let blinded_element =
                BlindedElement::<Ristretto255>::deserialize(&element.blinded_element)
                    .map_err(|_| IssueTokenResponseError::InvalidTokenRequest)?;
            blinded_elements.push(blinded_element);
        }

        let prepared_elements = server
            .batch_blind_evaluate_prepare(blinded_elements.iter())
            .collect::<Vec<_>>();
        let VoprfServerBatchEvaluateFinishResult { messages, proof } = server
            .batch_blind_evaluate_finish(&mut OsRng, blinded_elements.iter(), &prepared_elements)
            .map_err(|_| IssueTokenResponseError::InvalidTokenRequest)?;
        let evaluated_elements = messages
            .map(|m| EvaluatedElement {
                evaluated_element: m.serialize().into(),
            })
            .collect();

        Ok(TokenResponse {
            evaluated_elements,
            evaluated_proof: proof.serialize().into(),
        })
    }

    /// Redeems a token.
    ///
    /// # Errors
    /// Returns an error if the token is invalid.
    pub async fn redeem_token<BKS: BatchedKeyStore, NS: NonceStore>(
        &self,
        key_store: &BKS,
        nonce_store: &NS,
        token: BatchedToken,
    ) -> Result<(), RedeemTokenError> {
        if token.token_type() != TokenType::Batched {
            return Err(RedeemTokenError::InvalidToken);
        }
        if token.authenticator().len() != (NK) {
            return Err(RedeemTokenError::InvalidToken);
        }
        if nonce_store.exists(&token.nonce()).await {
            return Err(RedeemTokenError::DoubleSpending);
        }
        let token_input = TokenInput {
            token_type: token.token_type(),
            nonce: token.nonce(),
            challenge_digest: *token.challenge_digest(),
            key_id: *token.token_key_id(),
        };
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
    pub async fn set_key<BKS: BatchedKeyStore>(
        &self,
        key_store: &BKS,
        private_key: &[u8],
    ) -> Result<PublicKey, CreateKeypairError> {
        let server = VoprfServer::<Ristretto255>::new_with_key(private_key)
            .map_err(|_| CreateKeypairError::SeedError)?;
        let public_key = server.get_public_key();
        let token_key_id = key_id_to_token_key_id(&public_key_to_key_id(&server.get_public_key()));
        key_store.insert(token_key_id, server).await;
        Ok(public_key)
    }
}

#[test]
fn key_serialization() {
    let pk = Ristretto255::base_elem();
    let bytes = serialize_public_key(pk);
    let pk2 = deserialize_public_key(&bytes).unwrap();
    assert_eq!(pk, pk2);
}
