//! Server-side implementation of the Amortized Tokens protocol.

use generic_array::GenericArray;
use log::{debug, warn};
use rand::{RngCore, rngs::OsRng};
use sha2::digest::OutputSizeUser;
use subtle::ConstantTimeEq;
use typenum::Unsigned;
use voprf::{BlindedElement, Group, Result, VoprfServer, VoprfServerBatchEvaluateFinishResult};

use crate::{
    COLLISION_AVOIDANCE_ATTEMPTS, DEFAULT_MAX_BATCH_SIZE, NonceStore, TokenInput,
    common::{
        errors::{CreateKeypairError, IssueTokenResponseError, RedeemTokenError},
        private::{PrivateCipherSuite, PublicKey, public_key_to_token_key_id},
        store::PrivateKeyStore,
    },
    truncate_token_key_id,
};

use super::{AmortizedBatchTokenRequest, AmortizedBatchTokenResponse, AmortizedToken};

/// Server-side component of the batched token issuance protocol.
#[derive(Debug)]
pub struct Server<CS: PrivateCipherSuite> {
    max_batch_size: usize,
    _marker: std::marker::PhantomData<CS>,
}

impl<CS: PrivateCipherSuite> Default for Server<CS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<CS: PrivateCipherSuite> Server<CS> {
    fn server_from_seed(seed: &[u8], info: &[u8]) -> Result<VoprfServer<CS>, CreateKeypairError>
    where
        <CS::Group as Group>::Scalar: Send + Sync,
        <CS::Group as Group>::Elem: Send + Sync,
    {
        VoprfServer::<CS>::new_from_seed(seed, info)
            .inspect_err(|e| debug!(error:% = e; "Failed to create VOPRF server from seed"))
            .map_err(|source| CreateKeypairError::SeedError { source })
    }

    /// Create a new server. The new server does not contain any key material.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_batch_size: DEFAULT_MAX_BATCH_SIZE,
            _marker: std::marker::PhantomData,
        }
    }

    /// Creates a new server with a custom maximum batch size. The default is
    /// [`DEFAULT_MAX_BATCH_SIZE`](crate::DEFAULT_MAX_BATCH_SIZE).
    #[must_use]
    pub const fn with_max_batch_size(max_batch_size: usize) -> Self {
        Self {
            max_batch_size,
            _marker: std::marker::PhantomData,
        }
    }

    /// Creates a new keypair and inserts it into the key store.
    ///
    /// # Errors
    /// Returns an error if the seed is too long.
    pub async fn create_keypair<BKS: PrivateKeyStore<CS = CS>>(
        &self,
        key_store: &BKS,
    ) -> Result<PublicKey<CS>, CreateKeypairError>
    where
        <CS::Group as Group>::Scalar: Send + Sync,
        <CS::Group as Group>::Elem: Send + Sync,
    {
        for _ in 0..COLLISION_AVOIDANCE_ATTEMPTS {
            let mut seed = GenericArray::<_, <CS::Group as Group>::ScalarLen>::default();
            OsRng.fill_bytes(&mut seed);
            let server = Self::server_from_seed(&seed, b"PrivacyPass")?;
            let public_key = server.get_public_key();
            let truncated_token_key_id =
                truncate_token_key_id(&public_key_to_token_key_id::<CS>(&public_key));

            if key_store.get(&truncated_token_key_id).await.is_some() {
                continue;
            }

            if key_store.insert(truncated_token_key_id, server).await {
                return Ok(public_key);
            }
        }
        Err(CreateKeypairError::CollisionExhausted)
    }

    /// Creates a new keypair with explicit parameters and inserts it into the
    /// key store.
    #[cfg(feature = "kat")]
    pub async fn create_keypair_with_params<BKS: PrivateKeyStore<CS = CS>>(
        &self,
        key_store: &BKS,
        seed: &[u8],
        info: &[u8],
    ) -> Result<PublicKey<CS>, CreateKeypairError>
    where
        <CS::Group as Group>::Scalar: Send + Sync,
        <CS::Group as Group>::Elem: Send + Sync,
    {
        let server = Self::server_from_seed(seed, info)?;
        let public_key = server.get_public_key();
        let truncated_token_key_id =
            truncate_token_key_id(&public_key_to_token_key_id::<CS>(&server.get_public_key()));
        key_store.insert(truncated_token_key_id, server).await;
        Ok(public_key)
    }

    /// Issues a token response.
    ///
    /// # Errors
    /// Returns an error if the token request is invalid.
    pub async fn issue_token_response<BKS: PrivateKeyStore<CS = CS>>(
        &self,
        key_store: &BKS,
        token_request: AmortizedBatchTokenRequest<CS>,
    ) -> Result<AmortizedBatchTokenResponse<CS>, IssueTokenResponseError> {
        if token_request.token_type != CS::token_type() {
            return Err(IssueTokenResponseError::InvalidTokenType {
                expected: CS::token_type(),
                found: token_request.token_type,
            });
        }
        let batch_size = token_request.blinded_elements.len();
        if batch_size > self.max_batch_size {
            return Err(IssueTokenResponseError::BatchTooLarge {
                max: self.max_batch_size,
                size: batch_size,
            });
        }
        let server = key_store
            .get(&token_request.truncated_token_key_id)
            .await
            .ok_or(IssueTokenResponseError::KeyIdNotFound)?;

        let mut blinded_elements = Vec::new();
        for (idx, element) in token_request.blinded_elements.iter().enumerate() {
            let blinded_element = BlindedElement::<CS>::deserialize(&element.blinded_element)
                .inspect_err(
                    |e| warn!(error:% = e, index = idx; "Failed to deserialize blinded element"),
                )
                .map_err(|source| IssueTokenResponseError::InvalidBlindedMessage { source })?;
            blinded_elements.push(blinded_element);
        }

        let prepared_elements = server
            .batch_blind_evaluate_prepare(blinded_elements.iter())
            .collect::<Vec<_>>();
        let VoprfServerBatchEvaluateFinishResult { messages, proof } = server
            .batch_blind_evaluate_finish(&mut OsRng, blinded_elements.iter(), &prepared_elements)
            .inspect_err(|e| warn!(error:% = e; "Failed to batch evaluate blinded elements"))
            .map_err(|source| IssueTokenResponseError::BlindEvaluationFailed { source })?;

        let evaluated_elements = messages
            .map(|m| super::EvaluatedElement {
                _marker: std::marker::PhantomData,
                evaluated_element: m.serialize().to_vec(),
            })
            .collect();
        let evaluated_proof = proof.serialize().to_vec();

        Ok(AmortizedBatchTokenResponse {
            _marker: std::marker::PhantomData,
            evaluated_elements,
            evaluated_proof,
        })
    }

    /// Redeems a token.
    ///
    /// # Errors
    /// Returns an error if the token is invalid.
    pub async fn redeem_token<BKS: PrivateKeyStore, NS: NonceStore>(
        &self,
        key_store: &BKS,
        nonce_store: &NS,
        token: AmortizedToken<CS>,
    ) -> Result<(), RedeemTokenError> {
        let token_type = token.token_type();
        if token_type != CS::token_type() {
            return Err(RedeemTokenError::TokenTypeMismatch {
                expected: CS::token_type(),
                found: token_type,
            });
        }
        let auth_len = <<CS::Hash as OutputSizeUser>::OutputSize as Unsigned>::USIZE;
        let authenticator_len = token.authenticator().len();
        if authenticator_len != auth_len {
            return Err(RedeemTokenError::InvalidAuthenticatorLength {
                expected: auth_len,
                found: authenticator_len,
            });
        }
        let nonce = token.nonce();
        let token_input = TokenInput::new(
            token_type,
            nonce,
            *token.challenge_digest(),
            *token.token_key_id(),
        );

        if !nonce_store.reserve(&nonce).await {
            return Err(RedeemTokenError::DoubleSpending);
        }

        let crypto_result = async {
            let server = key_store
                .get(&truncate_token_key_id(token.token_key_id()))
                .await
                .ok_or(RedeemTokenError::KeyIdNotFound)?;
            let token_authenticator = server
                .evaluate(&token_input.serialize())
                .inspect_err(|e| {
                    warn!(error:% = e; "Failed to evaluate token during redemption");
                })
                .map_err(|source| RedeemTokenError::AuthenticatorDerivationFailed {
                    token_type,
                    source,
                })?
                .to_vec();
            let verified: bool = token.authenticator().ct_eq(&token_authenticator).into();
            if !verified {
                return Err(RedeemTokenError::AuthenticatorMismatch { token_type });
            }
            Ok(())
        }
        .await;

        match crypto_result {
            Ok(()) => {
                nonce_store.commit(&nonce).await;
                Ok(())
            }
            Err(e) => {
                nonce_store.release(&nonce).await;
                Err(e)
            }
        }
    }

    /// Sets a keypair with a given `private_key` into the key store.
    #[cfg(feature = "kat")]
    pub async fn set_key<BKS: PrivateKeyStore<CS = CS>>(
        &self,
        key_store: &BKS,
        private_key: &[u8],
    ) -> Result<PublicKey<CS>, CreateKeypairError>
    where
        <CS::Group as Group>::Scalar: Send + Sync,
        <CS::Group as Group>::Elem: Send + Sync,
    {
        let server = VoprfServer::<CS>::new_with_key(private_key)
            .inspect_err(|e| debug!(error:% = e; "Failed to create VOPRF server with key"))
            .map_err(|source| CreateKeypairError::SeedError { source })?;
        let public_key = server.get_public_key();
        let token_key_id = public_key_to_token_key_id::<CS>(&server.get_public_key());
        key_store
            .insert(truncate_token_key_id(&token_key_id), server)
            .await;
        Ok(public_key)
    }
}

#[cfg(test)]
mod tests {
    use crate::common::private::PrivateCipherSuite;
    use p384::NistP384;
    use voprf::{Group, Ristretto255};

    #[test]
    fn key_serialization() {
        // P384
        let pk = p384::NistP384::base_elem();
        key_serialization_cs::<NistP384>(pk);

        // Ristretto255
        let pk = Ristretto255::base_elem();
        key_serialization_cs::<Ristretto255>(pk);
    }

    #[cfg(test)]
    fn key_serialization_cs<CS: PrivateCipherSuite>(pk: <CS::Group as Group>::Elem)
    where
        <<CS as voprf::CipherSuite>::Group as voprf::Group>::Elem: std::cmp::PartialEq,
        <<CS as voprf::CipherSuite>::Group as voprf::Group>::Elem: std::fmt::Debug,
    {
        use crate::common::private::{deserialize_public_key, serialize_public_key};

        let bytes = serialize_public_key::<CS>(pk);
        let pk2 = deserialize_public_key::<CS>(&bytes).unwrap();
        assert_eq!(pk, pk2);
    }
}
