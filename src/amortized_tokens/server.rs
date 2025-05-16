//! Server-side implementation of the Amortized Tokens protocol.

use generic_array::GenericArray;
use rand::{RngCore, rngs::OsRng};
use sha2::digest::OutputSizeUser;
use typenum::Unsigned;
use voprf::{BlindedElement, Group, Result, VoprfServer, VoprfServerBatchEvaluateFinishResult};

use crate::{
    NonceStore, TokenInput,
    common::{
        errors::{CreateKeypairError, IssueTokenResponseError, RedeemTokenError},
        private::{PrivateCipherSuite, PublicKey, public_key_to_token_key_id},
        store::PrivateKeyStore,
    },
    truncate_token_key_id,
};

use super::{AmortizedBatchTokenRequest, AmortizedBatchTokenResponse, AmortizedToken};

/// Server-side component of the batched token issuance protocol.
#[derive(Default, Debug)]
pub struct Server<CS: PrivateCipherSuite> {
    _marker: std::marker::PhantomData<CS>,
}

impl<CS: PrivateCipherSuite> Server<CS> {
    /// Create a new server. The new server does not contain any key material.
    #[must_use]
    pub const fn new() -> Self {
        Self {
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
        let mut seed = GenericArray::<_, <CS::Group as Group>::ScalarLen>::default();
        OsRng.fill_bytes(&mut seed);
        self.create_keypair_internal(key_store, &seed, b"PrivacyPass")
            .await
    }

    /// Creates a new keypair and inserts it into the key store.
    async fn create_keypair_internal<BKS: PrivateKeyStore<CS = CS>>(
        &self,
        key_store: &BKS,
        seed: &[u8],
        info: &[u8],
    ) -> Result<PublicKey<CS>, CreateKeypairError>
    where
        <CS::Group as Group>::Scalar: Send + Sync,
        <CS::Group as Group>::Elem: Send + Sync,
    {
        let server = VoprfServer::<CS>::new_from_seed(seed, info)
            .map_err(|_| CreateKeypairError::SeedError)?;
        let public_key = server.get_public_key();
        let truncated_token_key_id =
            truncate_token_key_id(&public_key_to_token_key_id::<CS>(&server.get_public_key()));
        key_store.insert(truncated_token_key_id, server).await;
        Ok(public_key)
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
        self.create_keypair_internal(key_store, seed, info).await
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
            return Err(IssueTokenResponseError::InvalidTokenType);
        }
        let server = key_store
            .get(&token_request.truncated_token_key_id)
            .await
            .ok_or(IssueTokenResponseError::KeyIdNotFound)?;

        let mut blinded_elements = Vec::new();
        for element in token_request.blinded_elements.iter() {
            let blinded_element = BlindedElement::<CS>::deserialize(&element.blinded_element)
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
        let token_input = TokenInput {
            token_type: token.token_type(),
            nonce: token.nonce(),
            challenge_digest: *token.challenge_digest(),
            token_key_id: *token.token_key_id(),
        };
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
            .map_err(|_| CreateKeypairError::SeedError)?;
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
