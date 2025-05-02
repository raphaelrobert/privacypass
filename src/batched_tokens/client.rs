//! Client-side implementation of the Batched Tokens protocol.

use rand::{Rng, rngs::OsRng};
use voprf::{EvaluationElement, Group, Proof, Result, VoprfClient};

use crate::{
    ChallengeDigest, Nonce, PPCipherSuite, TokenInput,
    auth::{authenticate::TokenChallenge, authorize::Token},
    common::{
        errors::{IssueTokenError, IssueTokenRequestError},
        private::{PublicKey, public_key_to_token_key_id},
    },
    truncate_token_key_id,
};

use super::{BatchedToken, TokenRequest, TokenResponse};

/// Client-side state that is kept between the token requests and token responses.
pub struct TokenState<CS: PPCipherSuite> {
    clients: Vec<VoprfClient<CS>>,
    token_inputs: Vec<TokenInput>,
    challenge_digest: ChallengeDigest,
    public_key: PublicKey<CS>,
}

impl<CS: PPCipherSuite> std::fmt::Debug for TokenState<CS> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenState")
            .field("clients", &self.clients.len())
            .field("token_inputs", &self.token_inputs.len())
            .field("challenge_digest", &self.challenge_digest)
            .field("public_key", &"public key".to_string())
            .finish()
    }
}

impl<CS: PPCipherSuite> TokenRequest<CS> {
    /// Issue a new token request.
    ///
    /// # Errors
    /// Returns an error if the challenge is invalid.
    pub fn new(
        public_key: PublicKey<CS>,
        challenge: &TokenChallenge,
        nr: u16,
    ) -> Result<(TokenRequest<CS>, TokenState<CS>), IssueTokenRequestError> {
        let mut nonces = Vec::with_capacity(nr as usize);

        for _ in 0..nr {
            let nonce: Nonce = OsRng.r#gen();
            nonces.push(nonce);
        }

        Self::issue_token_request_internal(public_key, challenge, nonces, None)
    }

    /// Issue a token request.
    fn issue_token_request_internal(
        public_key: PublicKey<CS>,
        challenge: &TokenChallenge,
        nonces: Vec<Nonce>,
        _blinds: Option<Vec<<CS::Group as Group>::Scalar>>,
    ) -> Result<(TokenRequest<CS>, TokenState<CS>), IssueTokenRequestError> {
        let challenge_digest = challenge
            .digest()
            .map_err(|_| IssueTokenRequestError::InvalidTokenChallenge)?;

        let token_key_id = public_key_to_token_key_id::<CS::Group>(&public_key);

        let mut clients = Vec::with_capacity(nonces.len());
        let mut token_inputs = Vec::with_capacity(nonces.len());
        let mut blinded_elements = Vec::with_capacity(nonces.len());

        #[cfg(feature = "kat")]
        let mut blinds_iter = _blinds.iter().flatten();

        for nonce in nonces {
            // nonce = random(32)
            // challenge_digest = SHA256(challenge)
            // token_input = concat(0xF901, nonce, challenge_digest, token_key_id)
            // blind, blinded_element = client_context.Blind(token_input)

            let token_input = TokenInput::new(
                challenge.token_type(),
                nonce,
                challenge_digest,
                token_key_id,
            );

            let blind = VoprfClient::<CS>::blind(&token_input.serialize(), &mut OsRng)
                .map_err(|_| IssueTokenRequestError::BlindingError)?;

            #[cfg(feature = "kat")]
            let blind = if _blinds.is_some() {
                VoprfClient::<CS>::deterministic_blind_unchecked(
                    &token_input.serialize(),
                    *blinds_iter.next().unwrap(),
                )
                .map_err(|_| IssueTokenRequestError::BlindingError)?
            } else {
                blind
            };

            let serialized_blinded_element = blind.message.serialize().to_vec();
            let blinded_element = super::BlindedElement {
                _marker: std::marker::PhantomData,
                blinded_element: serialized_blinded_element,
            };

            clients.push(blind.state);
            token_inputs.push(token_input);
            blinded_elements.push(blinded_element);
        }

        let token_request = TokenRequest {
            token_type: challenge.token_type(),
            truncated_token_key_id: truncate_token_key_id(&token_key_id),
            blinded_elements,
        };

        let token_state = TokenState {
            clients,
            token_inputs,
            challenge_digest,
            public_key,
        };

        Ok((token_request, token_state))
    }

    #[cfg(feature = "kat")]
    /// Issue a token request.
    pub fn issue_token_request_with_params(
        public_key: PublicKey<CS>,
        challenge: &TokenChallenge,
        nonces: Vec<Nonce>,
        blind: Vec<<CS::Group as Group>::Scalar>,
    ) -> Result<(TokenRequest<CS>, TokenState<CS>), IssueTokenRequestError> {
        Self::issue_token_request_internal(public_key, challenge, nonces, Some(blind))
    }
}

impl<CS: PPCipherSuite> TokenResponse<CS> {
    /// Issue a token.
    ///
    /// # Errors
    /// Returns an error if the token response is invalid.
    pub fn issue_tokens(
        self,
        token_state: &TokenState<CS>,
    ) -> Result<Vec<BatchedToken<CS>>, IssueTokenError> {
        let mut evaluated_elements = Vec::new();
        for element in self.evaluated_elements.iter() {
            let evaluated_element =
                EvaluationElement::<CS>::deserialize(&element.evaluated_element)
                    .map_err(|_| IssueTokenError::InvalidTokenResponse)?;
            evaluated_elements.push(evaluated_element);
        }

        let proof = Proof::deserialize(&self.evaluated_proof)
            .map_err(|_| IssueTokenError::InvalidTokenResponse)?;

        let client_batch_finalize_result = VoprfClient::batch_finalize(
            &token_state
                .token_inputs
                .iter()
                .map(|token_input| token_input.serialize())
                .collect::<Vec<_>>(),
            &token_state.clients.to_vec(),
            &evaluated_elements,
            &proof,
            token_state.public_key,
        )
        .map_err(|_| IssueTokenError::InvalidTokenResponse)?
        .collect::<Result<Vec<_>>>()
        .map_err(|_| IssueTokenError::InvalidTokenResponse)?;

        let mut tokens = Vec::new();

        for (authenticator, token_input) in client_batch_finalize_result
            .iter()
            .zip(token_state.token_inputs.iter())
        {
            let token = Token::new(
                token_input.token_type,
                token_input.nonce,
                token_state.challenge_digest,
                token_input.token_key_id,
                authenticator.to_owned(),
            );
            tokens.push(token);
        }

        Ok(tokens)
    }
}
