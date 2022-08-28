//! Client-side implementation of the Batched Tokens protocol.

use rand::{rngs::OsRng, Rng};
use thiserror::Error;
use voprf::{EvaluationElement, Proof, Result, Ristretto255, VoprfClient};

use crate::{
    auth::{authenticate::TokenChallenge, authorize::Token},
    ChallengeDigest, KeyId, TokenInput, TokenType,
};

use super::{
    key_id_to_token_key_id, public_key_to_key_id, BatchedToken, BlindedElement, Nonce, PublicKey,
    TokenRequest, TokenResponse,
};

/// Client-side state that is kept between the token requests and token responses.
#[derive(Debug)]
pub struct TokenState {
    client: VoprfClient<Ristretto255>,
    token_input: TokenInput,
    challenge_digest: ChallengeDigest,
}

/// Errors that can occur when issuing token requests.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum IssueTokenRequestError {
    #[error("Token blinding error")]
    /// Error when blinding the token.
    BlindingError,
    #[error("Invalid TokenChallenge")]
    /// Error when the token challenge is invalid.
    InvalidTokenChallenge,
}

/// Errors that can occur when issuing tokens.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum IssueTokenError {
    #[error("Invalid TokenResponse")]
    /// Error when the token response is invalid.
    InvalidTokenResponse,
}

/// The client side of the batched token issuance protocol.
#[derive(Debug)]
pub struct Client {
    rng: OsRng,
    key_id: KeyId,
    public_key: PublicKey,
}

impl Client {
    /// Create a new client from a public key.
    #[must_use]
    pub fn new(public_key: PublicKey) -> Self {
        let key_id = public_key_to_key_id(&public_key);

        Self {
            rng: OsRng,
            key_id,
            public_key,
        }
    }

    /// Issue a token request.
    ///
    /// # Errors
    /// Returns an error if the token blinding fails.
    pub fn issue_token_request(
        &mut self,
        challenge: &TokenChallenge,
        nr: usize,
    ) -> Result<(TokenRequest, Vec<TokenState>), IssueTokenRequestError> {
        let challenge_digest = challenge
            .digest()
            .map_err(|_| IssueTokenRequestError::InvalidTokenChallenge)?;
        let mut blinded_elements = Vec::new();
        let mut token_states = Vec::new();

        for _ in 0..nr {
            // nonce = random(32)
            // challenge_digest = SHA256(challenge)
            // token_input = concat(0xF91A, nonce, challenge_digest, key_id)
            // blind, blinded_element = client_context.Blind(token_input)

            let nonce: Nonce = self.rng.gen();

            let token_input =
                TokenInput::new(TokenType::Batched, nonce, challenge_digest, self.key_id);

            let blind = VoprfClient::<Ristretto255>::blind(&token_input.serialize(), &mut self.rng)
                .map_err(|_| IssueTokenRequestError::BlindingError)?;

            let token_state = TokenState {
                client: blind.state,
                token_input,
                challenge_digest,
            };

            let blinded_element = BlindedElement {
                blinded_element: blind.message.serialize().into(),
            };

            blinded_elements.push(blinded_element);
            token_states.push(token_state);
        }

        let token_request = TokenRequest {
            token_type: TokenType::Batched,
            token_key_id: key_id_to_token_key_id(&self.key_id),
            blinded_elements: blinded_elements.into(),
        };

        Ok((token_request, token_states))
    }

    /// Issue a token.
    ///
    /// # Errors
    /// Returns an error if the token response is invalid.
    pub fn issue_token(
        &self,
        token_response: &TokenResponse,
        token_states: &[TokenState],
    ) -> Result<Vec<BatchedToken>, IssueTokenError> {
        let mut evaluated_elements = Vec::new();
        for element in token_response.evaluated_elements.iter() {
            let evaluated_element =
                EvaluationElement::<Ristretto255>::deserialize(&element.evaluated_element)
                    .map_err(|_| IssueTokenError::InvalidTokenResponse)?;
            evaluated_elements.push(evaluated_element);
        }

        let proof = Proof::deserialize(&token_response.evaluated_proof)
            .map_err(|_| IssueTokenError::InvalidTokenResponse)?;

        let client_batch_finalize_result = VoprfClient::batch_finalize(
            &token_states
                .iter()
                .map(|token_state| token_state.token_input.serialize())
                .into_iter()
                .collect::<Vec<_>>(),
            &token_states
                .iter()
                .map(|token_state| token_state.client.clone())
                .collect::<Vec<_>>(),
            &evaluated_elements,
            &proof,
            self.public_key,
        )
        .map_err(|_| IssueTokenError::InvalidTokenResponse)?
        .collect::<Result<Vec<_>>>()
        .map_err(|_| IssueTokenError::InvalidTokenResponse)?;

        let mut tokens = Vec::new();

        for (authenticator, token_state) in
            client_batch_finalize_result.iter().zip(token_states.iter())
        {
            let token = Token::new(
                TokenType::Batched,
                token_state.token_input.nonce,
                token_state.challenge_digest,
                token_state.token_input.key_id,
                *authenticator,
            );
            tokens.push(token);
        }

        Ok(tokens)
    }
}
