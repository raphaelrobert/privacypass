use async_trait::async_trait;
use blind_rsa_signatures::{KeyPair, Options, Signature};
use generic_array::ArrayLength;
use thiserror::*;

use crate::{auth::authorize::Token, KeyId, NonceStore, TokenInput, TokenType};

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
    /// Inserts a keypair with a given `key_id` into the key store.
    async fn insert(&self, key_id: KeyId, server: KeyPair);
    /// Returns a keypair with a given `key_id` from the key store.
    async fn get(&self, key_id: &KeyId) -> Option<KeyPair>;
}

const KEYSIZE_IN_BITS: usize = 2048;
const KEYSIZE_IN_BYTES: usize = KEYSIZE_IN_BITS / 8;

#[derive(Default)]
pub struct Server {}

impl Server {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn create_keypair<KS: KeyStore>(
        &mut self,
        key_store: &KS,
        key_id: KeyId,
    ) -> Result<KeyPair, CreateKeypairError> {
        let key_pair =
            KeyPair::generate(KEYSIZE_IN_BITS).map_err(|_| CreateKeypairError::SeedError)?;
        key_store.insert(key_id, key_pair.clone()).await;
        Ok(key_pair)
    }

    pub async fn issue_token_response<KS: KeyStore>(
        &mut self,
        key_store: &KS,
        token_request: TokenRequest,
    ) -> Result<TokenResponse, IssueTokenResponseError> {
        if token_request.token_type != TokenType::Public {
            return Err(IssueTokenResponseError::InvalidTokenType);
        }
        assert_eq!(token_request.token_type, TokenType::Public);
        let key_pair = key_store
            .get(&token_request.token_key_id)
            .await
            .ok_or(IssueTokenResponseError::KeyIdNotFound)?;

        // blind_sig = rsabssa_blind_sign(skI, TokenRequest.blinded_msg)
        let options = Options::default();
        let blind_sig = key_pair
            .sk
            .blind_sign(&token_request.blinded_msg, &options)
            .map_err(|_| IssueTokenResponseError::InvalidTokenRequest)?;
        Ok(TokenResponse {
            blind_sig: blind_sig.to_vec(),
        })
    }

    pub async fn redeem_token<KS: KeyStore, NS: NonceStore, Nk: ArrayLength<u8>>(
        &mut self,
        key_store: &KS,
        nonce_store: &NS,
        token: Token<Nk>,
    ) -> Result<(), RedeemTokenError> {
        if token.token_type() != TokenType::Public {
            return Err(RedeemTokenError::InvalidToken);
        }
        if token.authenticator().len() != KEYSIZE_IN_BYTES {
            return Err(RedeemTokenError::InvalidToken);
        }
        if nonce_store.exists(&token.nonce()).await {
            return Err(RedeemTokenError::DoubleSpending);
        }
        let token_input = TokenInput {
            token_type: token.token_type(),
            nonce: token.nonce(),
            challenge_digest: *token.challenge_digest(),
            key_id: token.token_key_id(),
        };
        let key_pair = key_store
            .get(&token.token_key_id())
            .await
            .ok_or(RedeemTokenError::KeyIdNotFound)?;

        let options = Options::default();
        let signature = Signature(token.authenticator().to_vec());

        signature
            .verify(&key_pair.pk, &token_input.serialize(), &options)
            .map_err(|_| RedeemTokenError::InvalidToken)?;
        nonce_store.insert(token.nonce()).await;
        Ok(())
    }
}
