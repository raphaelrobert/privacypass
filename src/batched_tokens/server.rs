use async_trait::async_trait;
use generic_array::ArrayLength;
use generic_array::GenericArray;
use rand::{rngs::OsRng, RngCore};
use std::marker::PhantomData;
use thiserror::*;
use voprf::*;

use crate::{
    auth::authorize::Token, batched_tokens::EvaluatedElement, KeyId, NonceStore, TokenType,
};

use super::{TokenInput, TokenRequest, TokenResponse};

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
    async fn insert(&mut self, key_id: KeyId, server: VoprfServer<Ristretto255>);
    /// Returns a keypair with a given `key_id` from the key store.
    async fn get(&self, key_id: &KeyId) -> Option<VoprfServer<Ristretto255>>;
}

#[derive(Default)]
pub struct Server {
    rng: OsRng,
    cs: PhantomData<Ristretto255>,
}

impl Server {
    pub fn new() -> Self {
        Self {
            rng: OsRng,
            cs: PhantomData,
        }
    }

    pub async fn create_keypair<KS: KeyStore>(
        &mut self,
        key_store: &mut KS,
        key_id: KeyId,
    ) -> Result<<Ristretto255 as Group>::Elem, CreateKeypairError> {
        let mut seed = GenericArray::<_, <Ristretto255 as Group>::ScalarLen>::default();
        self.rng.fill_bytes(&mut seed);
        let server = VoprfServer::<Ristretto255>::new_from_seed(&seed, b"PrivacyPass")
            .map_err(|_| CreateKeypairError::SeedError)?;
        let public_key = server.get_public_key();
        key_store.insert(key_id, server).await;
        Ok(public_key)
    }

    pub async fn issue_token_response<KS: KeyStore>(
        &mut self,
        key_store: &KS,
        token_request: TokenRequest,
    ) -> Result<TokenResponse, IssueTokenResponseError> {
        if token_request.token_type != TokenType::Batched {
            return Err(IssueTokenResponseError::InvalidTokenType);
        }
        assert_eq!(token_request.token_type, TokenType::Batched);
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
            .batch_blind_evaluate_finish(&mut self.rng, blinded_elements.iter(), &prepared_elements)
            .map_err(|_| IssueTokenResponseError::InvalidTokenRequest)?;
        let evaluated_elements: Vec<EvaluatedElement> = messages
            .map(|m| EvaluatedElement {
                evaluated_element: m.serialize().to_vec(),
            })
            .collect();

        Ok(TokenResponse {
            evaluated_elements,
            evaluated_proof: proof.serialize().to_vec(),
        })
    }

    pub async fn redeem_token<KS: KeyStore, NS: NonceStore, Nk: ArrayLength<u8>>(
        &mut self,
        key_store: &mut KS,
        nonce_store: &mut NS,
        token: Token<Nk>,
    ) -> Result<(), RedeemTokenError> {
        if token.token_type() != TokenType::Batched {
            return Err(RedeemTokenError::InvalidToken);
        }
        if token.authenticator().len() != 64 {
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
        let server = key_store
            .get(&token.token_key_id())
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
