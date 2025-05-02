//! Server-side implementation of Privately Verifiable Token protocol.

use generic_array::ArrayLength;
use generic_array::GenericArray;
use rand::{RngCore, rngs::OsRng};
use sha2::digest::OutputSizeUser;
use typenum::Unsigned;
use voprf::{BlindedElement, Group, Result, VoprfServer};

use crate::{
    NonceStore, PPCipherSuite, TokenInput,
    auth::authorize::Token,
    common::{
        errors::{CreateKeypairError, IssueTokenResponseError, RedeemTokenError},
        private::{PublicKey, public_key_to_token_key_id},
        store::PrivateKeyStore,
    },
    truncate_token_key_id,
};

use super::{TokenRequest, TokenResponse};

/// Server side implementation of Privately Verifiable Token protocol.
#[derive(Default, Debug)]
pub struct Server<CS: PPCipherSuite> {
    _marker: std::marker::PhantomData<CS>,
}

impl<CS: PPCipherSuite> Server<CS> {
    /// Creates a new server.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }

    /// Creates a new keypair and inserts it into the key store.
    ///
    /// # Errors
    /// Returns an error if creating the keypair failed.
    pub async fn create_keypair<PKS: PrivateKeyStore<CS = CS>>(
        &self,
        key_store: &PKS,
    ) -> Result<PublicKey<CS>, CreateKeypairError> {
        let mut seed = GenericArray::<_, <CS::Group as Group>::ScalarLen>::default();
        OsRng.fill_bytes(&mut seed);
        self.create_keypair_internal(key_store, &seed, b"PrivacyPass")
            .await
    }

    /// Creates a new keypair and inserts it into the key store.
    async fn create_keypair_internal<PKS: PrivateKeyStore<CS = CS>>(
        &self,
        key_store: &PKS,
        seed: &[u8],
        info: &[u8],
    ) -> Result<PublicKey<CS>, CreateKeypairError> {
        let server = VoprfServer::<CS>::new_from_seed(seed, info)
            .map_err(|_| CreateKeypairError::SeedError)?;
        let public_key = server.get_public_key();
        let truncated_token_key_id = truncate_token_key_id(
            &public_key_to_token_key_id::<CS::Group>(&server.get_public_key()),
        );
        key_store.insert(truncated_token_key_id, server).await;
        Ok(public_key)
    }

    /// Creates a new keypair with explicit parameters and inserts it into the
    /// key store.
    #[cfg(feature = "kat")]
    pub async fn create_keypair_with_params<PKS: PrivateKeyStore<CS = CS>>(
        &self,
        key_store: &PKS,
        seed: &[u8],
        info: &[u8],
    ) -> Result<PublicKey<CS>, CreateKeypairError> {
        self.create_keypair_internal(key_store, seed, info).await
    }

    /// Issues a token response.
    ///
    /// # Errors
    /// Returns an error if the token request is invalid.
    pub async fn issue_token_response<PKS: PrivateKeyStore<CS = CS>>(
        &self,
        key_store: &PKS,
        token_request: TokenRequest<CS>,
    ) -> Result<TokenResponse<CS>, IssueTokenResponseError> {
        if token_request.token_type != CS::token_type() {
            return Err(IssueTokenResponseError::InvalidTokenType);
        }
        let server = key_store
            .get(&token_request.truncated_token_key_id)
            .await
            .ok_or(IssueTokenResponseError::KeyIdNotFound)?;
        let blinded_element = BlindedElement::<CS>::deserialize(&token_request.blinded_msg)
            .map_err(|_| IssueTokenResponseError::InvalidTokenRequest)?;
        let evaluated_result = server.blind_evaluate(&mut OsRng, &blinded_element);

        Ok(TokenResponse {
            _marker: std::marker::PhantomData,
            evaluate_msg: evaluated_result.message.serialize().to_vec(),
            evaluate_proof: evaluated_result.proof.serialize().to_vec(),
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
        if token.token_type() != CS::token_type() {
            return Err(RedeemTokenError::InvalidToken);
        }
        let auth_len = <<CS::Hash as OutputSizeUser>::OutputSize as Unsigned>::USIZE;
        if token.authenticator().len() != auth_len {
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
    pub async fn set_key<PKS: PrivateKeyStore<CS = CS>>(
        &self,
        key_store: &PKS,
        private_key: &[u8],
    ) -> Result<PublicKey<CS>, CreateKeypairError> {
        let server = VoprfServer::<CS>::new_with_key(private_key)
            .map_err(|_| CreateKeypairError::SeedError)?;
        let public_key = server.get_public_key();
        let truncated_token_key_id = truncate_token_key_id(
            &public_key_to_token_key_id::<CS::Group>(&server.get_public_key()),
        );
        key_store.insert(truncated_token_key_id, server).await;
        Ok(public_key)
    }
}
