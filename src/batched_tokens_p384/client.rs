//! Client-side implementation of the Batched Tokens protocol.

use p384::NistP384;
use rand::{rngs::OsRng, Rng};
use thiserror::Error;
use voprf::{EvaluationElement, Proof, Result, VoprfClient};

use crate::{
    auth::{authenticate::TokenChallenge, authorize::Token},
    ChallengeDigest, TokenInput, TokenKeyId, TokenType,
};

use super::{
    public_key_to_token_key_id, truncate_token_key_id, BatchedToken, Nonce, PublicKey,
    TokenRequest, TokenResponse,
};

/// Client-side state that is kept between the token requests and token responses.
#[derive(Debug)]
pub struct TokenState {
    client: VoprfClient<NistP384>,
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
    token_key_id: TokenKeyId,
    public_key: PublicKey,
}

impl Client {
    /// Create a new client from a public key.
    #[must_use]
    pub fn new(public_key: PublicKey) -> Self {
        let token_key_id = public_key_to_token_key_id(&public_key);

        Self {
            token_key_id,
            public_key,
        }
    }

    /// Issue a token request.
    ///
    /// # Errors
    /// Returns an error if the token blinding fails.
    pub fn issue_token_request(
        &self,
        challenge: &TokenChallenge,
        nr: u16,
    ) -> Result<(TokenRequest, Vec<TokenState>), IssueTokenRequestError> {
        let mut nonces = Vec::with_capacity(nr as usize);

        for _ in 0..nr {
            let nonce: Nonce = OsRng.gen();
            nonces.push(nonce);
        }

        self.issue_token_request_internal(challenge, nonces, None)
    }

    /// Issue a token request.
    fn issue_token_request_internal(
        &self,
        challenge: &TokenChallenge,
        nonces: Vec<Nonce>,
        _blinds: Option<Vec<<NistP384 as voprf::Group>::Scalar>>,
    ) -> Result<(TokenRequest, Vec<TokenState>), IssueTokenRequestError> {
        let challenge_digest = challenge
            .digest()
            .map_err(|_| IssueTokenRequestError::InvalidTokenChallenge)?;

        let mut blinded_elements = Vec::new();
        let mut token_states = Vec::new();

        #[cfg(feature = "kat")]
        let mut blinds_iter = _blinds.iter().flatten();

        for nonce in nonces {
            // nonce = random(32)
            // challenge_digest = SHA256(challenge)
            // token_input = concat(0xF901, nonce, challenge_digest, token_key_id)
            // blind, blinded_element = client_context.Blind(token_input)

            let token_input = TokenInput::new(
                TokenType::BatchedTokenP384,
                nonce,
                challenge_digest,
                self.token_key_id,
            );

            let blinded_element =
                VoprfClient::<NistP384>::blind(&token_input.serialize(), &mut OsRng)
                    .map_err(|_| IssueTokenRequestError::BlindingError)?;

            #[cfg(feature = "kat")]
            let blinded_element = if _blinds.is_some() {
                VoprfClient::<NistP384>::deterministic_blind_unchecked(
                    &token_input.serialize(),
                    *blinds_iter.next().unwrap(),
                )
                .map_err(|_| IssueTokenRequestError::BlindingError)?
            } else {
                blinded_element
            };

            let token_state = TokenState {
                client: blinded_element.state,
                token_input,
                challenge_digest,
            };

            let blinded_element = super::BlindedElement {
                blinded_element: blinded_element.message.serialize().into(),
            };

            blinded_elements.push(blinded_element);
            token_states.push(token_state);
        }

        let token_request = TokenRequest {
            token_type: TokenType::BatchedTokenP384,
            truncated_token_key_id: truncate_token_key_id(&self.token_key_id),
            blinded_elements: blinded_elements.into(),
        };

        Ok((token_request, token_states))
    }

    #[cfg(feature = "kat")]
    /// Issue a token request.
    pub fn issue_token_request_with_params(
        &self,
        challenge: &TokenChallenge,
        nonces: Vec<Nonce>,
        blind: Vec<<NistP384 as voprf::Group>::Scalar>,
    ) -> Result<(TokenRequest, Vec<TokenState>), IssueTokenRequestError> {
        self.issue_token_request_internal(challenge, nonces, Some(blind))
    }

    /// Issue a token.
    ///
    /// # Errors
    /// Returns an error if the token response is invalid.
    pub fn issue_tokens(
        &self,
        token_response: &TokenResponse,
        token_states: &[TokenState],
    ) -> Result<Vec<BatchedToken>, IssueTokenError> {
        let mut evaluated_elements = Vec::new();
        for element in token_response.evaluated_elements.iter() {
            let evaluated_element =
                EvaluationElement::<NistP384>::deserialize(&element.evaluated_element)
                    .map_err(|_| IssueTokenError::InvalidTokenResponse)?;
            evaluated_elements.push(evaluated_element);
        }

        let proof = Proof::deserialize(&token_response.evaluated_proof)
            .map_err(|_| IssueTokenError::InvalidTokenResponse)?;

        let client_batch_finalize_result = VoprfClient::batch_finalize(
            &token_states
                .iter()
                .map(|token_state| token_state.token_input.serialize())
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
                TokenType::BatchedTokenP384,
                token_state.token_input.nonce,
                token_state.challenge_digest,
                token_state.token_input.token_key_id,
                *authenticator,
            );
            tokens.push(token);
        }

        Ok(tokens)
    }
}
