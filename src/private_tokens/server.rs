use async_trait::async_trait;
use generic_array::GenericArray;
use rand::{rngs::OsRng, RngCore};
use sha2::digest::{
    core_api::BlockSizeUser,
    typenum::{IsLess, IsLessOrEqual, U256},
    OutputSizeUser,
};
use std::marker::PhantomData;
use thiserror::*;
use voprf::*;

use super::{KeyId, Nonce, Token, TokenInput, TokenRequest, TokenResponse};

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
pub trait KeyStore<CS: CipherSuite>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// Inserts a keypair with a given `key_id` into the key store.
    async fn insert(&mut self, key_id: KeyId, server: VoprfServer<CS>);
    /// Returns a keypair with a given `key_id` from the key store.
    async fn get(&self, key_id: &KeyId) -> Option<VoprfServer<CS>>;
}

#[async_trait]
pub trait NonceStore {
    /// Returns `true` if the nonce exists in the nonce store and `false` otherwise.
    async fn exists(&self, nonce: &Nonce) -> bool;
    /// Inserts a new nonce in the nonce store.
    async fn insert(&mut self, nonce: Nonce);
}

#[derive(Default)]
pub struct Server<CS: CipherSuite>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    rng: OsRng,
    cs: PhantomData<CS>,
}

impl<CS: CipherSuite> Server<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    <CS::Group as Group>::ScalarLen: std::ops::Add,
    <<CS::Group as Group>::ScalarLen as std::ops::Add>::Output:
        sha2::digest::generic_array::ArrayLength<u8>,
{
    pub fn new() -> Self {
        Self {
            rng: OsRng,
            cs: PhantomData,
        }
    }

    pub async fn create_keypair<KS: KeyStore<CS>>(
        &mut self,
        key_store: &mut KS,
        key_id: KeyId,
    ) -> Result<<CS::Group as Group>::Elem, CreateKeypairError> {
        let mut seed = GenericArray::<_, <CS::Group as Group>::ScalarLen>::default();
        self.rng.fill_bytes(&mut seed);
        let server = VoprfServer::<CS>::new_from_seed(&seed, b"PrivacyPass")
            .map_err(|_| CreateKeypairError::SeedError)?;
        let public_key = server.get_public_key();
        key_store.insert(key_id, server).await;
        Ok(public_key)
    }

    pub async fn issue_token_response<KS: KeyStore<CS>>(
        &mut self,
        key_store: &KS,
        token_request: TokenRequest,
    ) -> Result<TokenResponse, IssueTokenResponseError> {
        assert_eq!(token_request.token_type, 1);
        let server = key_store
            .get(&token_request.token_key_id)
            .await
            .ok_or(IssueTokenResponseError::KeyIdNotFound)?;
        let blinded_element = BlindedElement::<CS>::deserialize(&token_request.blinded_msg)
            .map_err(|_| IssueTokenResponseError::InvalidTokenRequest)?;
        let evaluated_result = server.blind_evaluate(&mut self.rng, &blinded_element);
        Ok(TokenResponse {
            evaluate_msg: evaluated_result.message.serialize().to_vec(),
            evaluate_proof: evaluated_result.proof.serialize().to_vec(),
        })
    }

    pub async fn redeem_token<KS: KeyStore<CS>, NS: NonceStore>(
        &mut self,
        key_store: &mut KS,
        nonce_store: &mut NS,
        token: Token,
    ) -> Result<(), RedeemTokenError> {
        if token.token_type != 1 {
            return Err(RedeemTokenError::InvalidToken);
        }
        if token.authenticator.len() != <CS::Hash as OutputSizeUser>::output_size() {
            return Err(RedeemTokenError::InvalidToken);
        }
        let nonce: Nonce = token
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| RedeemTokenError::InvalidToken)?;
        if nonce_store.exists(&nonce).await {
            return Err(RedeemTokenError::DoubleSpending);
        }
        let token_input = TokenInput {
            token_type: token.token_type,
            nonce,
            context: token.challenge_digest,
            key_id: token.token_key_id,
        };
        let server = key_store
            .get(&token.token_key_id)
            .await
            .ok_or(RedeemTokenError::KeyIdNotFound)?;
        let token_authenticator = server
            .evaluate(&token_input.serialize())
            .map_err(|_| RedeemTokenError::InvalidToken)?
            .to_vec();
        if token.authenticator == token_authenticator {
            nonce_store.insert(nonce).await;
            Ok(())
        } else {
            Err(RedeemTokenError::InvalidToken)
        }
    }
}
