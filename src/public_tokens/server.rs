//! Server-side implementation of Publicly Verifiable Token protocol.

use async_trait::async_trait;
use blind_rsa_signatures::{KeyPair, Options, PublicKey, Signature};
use generic_array::ArrayLength;
use rand::{CryptoRng, RngCore, rngs::OsRng};

use crate::{
    NonceStore, TokenInput, TokenType, TruncatedTokenKeyId,
    auth::authorize::Token,
    common::errors::{CreateKeypairError, IssueTokenResponseError, RedeemTokenError},
};

use super::{NK, TokenRequest, TokenResponse, public_key_to_token_key_id, truncate_token_key_id};

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
    /// Returns all public keys with a given `truncated_token_key_id` from the key store.
    async fn get(&self, truncated_token_key_id: &TruncatedTokenKeyId) -> Vec<PublicKey>;
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
    ) -> Result<PublicKey, CreateKeypairError> {
        let attempts_limit = 100;
        for _ in 0..attempts_limit {
            let key_pair = KeyPair::generate(rng, KEYSIZE_IN_BITS)
                .map_err(|_| CreateKeypairError::SeedError)?;
            let truncated_token_key_id =
                truncate_token_key_id(&public_key_to_token_key_id(&key_pair.pk));

            if key_store.get(&truncated_token_key_id).await.is_some() {
                continue;
            }

            key_store
                .insert(truncated_token_key_id, key_pair.clone())
                .await;
            return Ok(key_pair.pk);
        }
        Err(CreateKeypairError::SeedError)
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
        if token_request.token_type != TokenType::Public {
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
        if token.token_type() != TokenType::Public {
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

        let truncated_token_key_id = truncate_token_key_id(token.token_key_id());
        let public_keys = key_store.get(&truncated_token_key_id).await;
        if public_keys.is_empty() {
            return Err(RedeemTokenError::KeyIdNotFound);
        }

        let options = Options::default();
        let signature = Signature(token.authenticator().to_vec());
        let token_input_bytes = token_input.serialize();

        let mut verified = false;
        for public_key in public_keys {
            if signature
                .verify(&public_key, None, token_input_bytes.clone(), &options)
                .is_ok()
            {
                verified = true;
                break;
            }
        }

        if !verified {
            return Err(RedeemTokenError::InvalidToken);
        }

        nonce_store.insert(token.nonce()).await;
        Ok(())
    }
}
