use async_trait::async_trait;
use generic_array::GenericArray;
use rand::{rngs::OsRng, RngCore};
use thiserror::*;
use voprf::*;

use crate::{batched_tokens::EvaluatedElement, NonceStore, TokenInput, TokenKeyId, TokenType};

use super::{
    key_id_to_token_key_id, public_key_to_key_id, BatchedToken, PublicKey, TokenRequest,
    TokenResponse,
};

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
    async fn insert(&self, token_key_id: TokenKeyId, server: VoprfServer<Ristretto255>);
    /// Returns a keypair with a given `token_key_id` from the key store.
    async fn get(&self, token_key_id: &TokenKeyId) -> Option<VoprfServer<Ristretto255>>;
}

pub fn serialize_public_key(public_key: PublicKey) -> Vec<u8> {
    <Ristretto255 as Group>::serialize_elem(public_key).to_vec()
}

pub fn deserialize_public_key(slice: &[u8]) -> Result<PublicKey, Error> {
    <Ristretto255 as Group>::deserialize_elem(slice)
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
        key_store: &mut KS,
    ) -> Result<PublicKey, CreateKeypairError> {
        let mut seed = GenericArray::<_, <Ristretto255 as Group>::ScalarLen>::default();
        self.rng.fill_bytes(&mut seed);
        let server = VoprfServer::<Ristretto255>::new_from_seed(&seed, b"PrivacyPass")
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

    pub async fn redeem_token<KS: KeyStore, NS: NonceStore>(
        &self,
        key_store: &KS,
        nonce_store: &NS,
        token: BatchedToken,
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
}

#[test]
fn key_serialization() {
    let pk = Ristretto255::base_elem();
    let bytes = serialize_public_key(pk);
    let pk2 = deserialize_public_key(&bytes).unwrap();
    assert_eq!(pk, pk2);
}
