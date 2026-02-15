//! Server-side implementation of Publicly Verifiable Token protocol.

use async_trait::async_trait;
use blind_rsa_signatures::reexports::rand::CryptoRng;
use blind_rsa_signatures::{
    Deterministic, KeyPair as GenericKeyPair, PSS, PublicKey as GenericPublicKey, Sha384, Signature,
};
use generic_array::ArrayLength;

type KeyPair = GenericKeyPair<Sha384, PSS, Deterministic>;
type PublicKey = GenericPublicKey<Sha384, PSS, Deterministic>;

use crate::{
    COLLISION_AVOIDANCE_ATTEMPTS, NonceStore, TokenInput, TokenType, TruncatedTokenKeyId,
    auth::authorize::Token,
    common::errors::{CreateKeypairError, IssueTokenResponseError, RedeemTokenError},
};

use super::{NK, TokenRequest, TokenResponse, public_key_to_token_key_id, truncate_token_key_id};

/// Minimal trait for a key store to store key material on the server-side. Note
/// that the store requires inner mutability.
#[async_trait]

pub trait IssuerKeyStore: Send + Sync {
    /// Inserts a keypair with a given `truncated_token_key_id` into the key
    /// store, only if it does not collide with an existing
    /// `truncated_token_key_id`.
    ///
    /// Returns `true` if the key was inserted, `false` if a collision occurred.
    async fn insert(&self, truncated_token_key_id: TruncatedTokenKeyId, server: KeyPair) -> bool;
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
    public_key.to_spki().unwrap()
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
    pub async fn create_keypair<IKS: IssuerKeyStore, R: CryptoRng>(
        &self,
        rng: &mut R,
        key_store: &IKS,
    ) -> Result<PublicKey, CreateKeypairError> {
        for _ in 0..COLLISION_AVOIDANCE_ATTEMPTS {
            let key_pair = KeyPair::generate(rng, KEYSIZE_IN_BITS)
                .map_err(|source| CreateKeypairError::KeyGenerationFailed { source })?;
            let truncated_token_key_id =
                truncate_token_key_id(&public_key_to_token_key_id(&key_pair.pk));

            if key_store.get(&truncated_token_key_id).await.is_some() {
                continue;
            }

            let public_key = key_pair.pk.clone();

            if key_store.insert(truncated_token_key_id, key_pair).await {
                return Ok(public_key);
            }
        }
        Err(CreateKeypairError::CollisionExhausted)
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
        if token_request.token_type != TokenType::Public {
            return Err(IssueTokenResponseError::InvalidTokenType {
                expected: TokenType::Public,
                found: token_request.token_type,
            });
        }
        let key_pair = key_store
            .get(&token_request.truncated_token_key_id)
            .await
            .ok_or(IssueTokenResponseError::KeyIdNotFound)?;

        // blind_sig = rsabssa_blind_sign(skI, TokenRequest.blinded_msg)
        let blind_signature = key_pair
            .sk
            .blind_sign(token_request.blinded_msg)
            .map_err(|source| IssueTokenResponseError::BlindSignatureFailed { source })?;

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
    pub async fn redeem_token<OKS: OriginKeyStore, NS: NonceStore, Nk: ArrayLength>(
        &self,
        key_store: &OKS,
        nonce_store: &NS,
        token: Token<Nk>,
    ) -> Result<(), RedeemTokenError> {
        let token_type = token.token_type();
        if token_type != TokenType::Public {
            return Err(RedeemTokenError::TokenTypeMismatch {
                expected: TokenType::Public,
                found: token_type,
            });
        }
        let authenticator_len = token.authenticator().len();
        if authenticator_len != KEYSIZE_IN_BYTES {
            return Err(RedeemTokenError::InvalidAuthenticatorLength {
                expected: KEYSIZE_IN_BYTES,
                found: authenticator_len,
            });
        }
        if nonce_store.exists(&token.nonce()).await {
            return Err(RedeemTokenError::DoubleSpending);
        }
        let token_input = TokenInput::new(
            token_type,
            token.nonce(),
            *token.challenge_digest(),
            *token.token_key_id(),
        );

        let truncated_token_key_id = truncate_token_key_id(token.token_key_id());
        let public_keys = key_store.get(&truncated_token_key_id).await;
        if public_keys.is_empty() {
            return Err(RedeemTokenError::KeyIdNotFound);
        }

        let signature = Signature(token.authenticator().to_vec());
        let token_input_bytes = token_input.serialize();

        let verified = public_keys.iter().any(|public_key| {
            public_key
                .verify(&signature, None, &token_input_bytes)
                .is_ok()
        });

        if !verified {
            return Err(RedeemTokenError::InvalidSignature { token_type });
        }

        nonce_store.insert(token.nonce()).await;
        Ok(())
    }
}
