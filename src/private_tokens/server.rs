use async_trait::async_trait;
use generic_array::ArrayLength;
use generic_array::GenericArray;
use p256::NistP256;
use rand::{rngs::OsRng, RngCore};
use thiserror::*;
use voprf::*;

use crate::TokenInput;
use crate::{auth::authorize::Token, NonceStore, TokenKeyId, TokenType};

use super::key_id_to_token_key_id;
use super::public_key_to_key_id;
use super::PublicKey;
use super::{TokenRequest, TokenResponse};

#[derive(Error, Debug, PartialEq)]
pub enum CreateKeypairError {
    #[error("Seed is too long")]
    SeedError,
}

#[derive(Error, Debug, PartialEq)]
pub enum IssueTokenResponseError {
    #[error("Key ID not found")]
    KeyIdNotFound,
    #[error("Invalid TokenRequest")]
    InvalidTokenRequest,
    #[error("Invalid toke type")]
    InvalidTokenType,
}

#[derive(Error, Debug, PartialEq)]
pub enum RedeemTokenError {
    #[error("Key ID not found")]
    KeyIdNotFound,
    #[error("The token has already been redeemed")]
    DoubleSpending,
    #[error("The token is invalid")]
    InvalidToken,
}

#[async_trait]
pub trait KeyStore {
    /// Inserts a keypair with a given `token_key_id` into the key store.
    async fn insert(&self, token_key_id: TokenKeyId, server: VoprfServer<NistP256>);
    /// Returns a keypair with a given `token_key_id` from the key store.
    async fn get(&self, token_key_id: &TokenKeyId) -> Option<VoprfServer<NistP256>>;
}

pub fn serialize_public_key(public_key: PublicKey) -> Vec<u8> {
    <NistP256 as Group>::serialize_elem(public_key).to_vec()
}

pub fn deserialize_public_key(slice: &[u8]) -> Result<PublicKey, Error> {
    <NistP256 as Group>::deserialize_elem(slice)
}

#[derive(Default)]
pub struct Server {
    rng: OsRng,
}

impl Server {
    pub fn new() -> Self {
        Self { rng: OsRng }
    }

    pub async fn create_keypair<KS: KeyStore>(
        &mut self,
        key_store: &KS,
    ) -> Result<PublicKey, CreateKeypairError> {
        let mut seed = GenericArray::<_, <NistP256 as Group>::ScalarLen>::default();
        self.rng.fill_bytes(&mut seed);
        let server = VoprfServer::<NistP256>::new_from_seed(&seed, b"PrivacyPass")
            .map_err(|_| CreateKeypairError::SeedError)?;
        let public_key = server.get_public_key();
        let token_key_id = key_id_to_token_key_id(&public_key_to_key_id(&server.get_public_key()));
        key_store.insert(token_key_id, server).await;
        Ok(public_key)
    }

    pub async fn issue_token_response<KS: KeyStore>(
        &mut self,
        key_store: &KS,
        token_request: TokenRequest,
    ) -> Result<TokenResponse, IssueTokenResponseError> {
        if token_request.token_type != TokenType::Private {
            return Err(IssueTokenResponseError::InvalidTokenType);
        }
        assert_eq!(token_request.token_type, TokenType::Private);
        let server = key_store
            .get(&token_request.token_key_id)
            .await
            .ok_or(IssueTokenResponseError::KeyIdNotFound)?;
        let blinded_element = BlindedElement::<NistP256>::deserialize(&token_request.blinded_msg)
            .map_err(|_| IssueTokenResponseError::InvalidTokenRequest)?;
        let evaluated_result = server.blind_evaluate(&mut self.rng, &blinded_element);
        Ok(TokenResponse {
            evaluate_msg: evaluated_result.message.serialize().into(),
            evaluate_proof: evaluated_result.proof.serialize().into(),
        })
    }

    pub async fn redeem_token<KS: KeyStore, NS: NonceStore, Nk: ArrayLength<u8>>(
        &mut self,
        key_store: &KS,
        nonce_store: &NS,
        token: Token<Nk>,
    ) -> Result<(), RedeemTokenError> {
        if token.token_type() != TokenType::Private {
            return Err(RedeemTokenError::InvalidToken);
        }
        if token.authenticator().len() != 32 {
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
}
