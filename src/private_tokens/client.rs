//! Client-side implementation of the Privately Verifiable Token protocol.

use p384::NistP384;
use rand::{rngs::OsRng, Rng};
use thiserror::Error;
use voprf::{EvaluationElement, Proof, Result, VoprfClient};

use crate::{
    auth::{authenticate::TokenChallenge, authorize::Token},
    ChallengeDigest, TokenInput, TokenType,
};

use super::{
    public_key_to_token_key_id, truncate_token_key_id, Nonce, PrivateToken, PublicKey,
    TokenRequest, TokenResponse,
};

/// Client-side state that is kept between the token requests and token responses.
#[derive(Debug)]
pub struct TokenState {
    token_input: TokenInput,
    challenge_digest: ChallengeDigest,
    client: VoprfClient<NistP384>,
    public_key: PublicKey,
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

impl TokenRequest {
    /// Issue a new token request.
    ///
    /// # Errors
    /// Returns an error if the challenge is invalid.
    pub fn new(
        public_key: PublicKey,
        challenge: &TokenChallenge,
    ) -> Result<(TokenRequest, TokenState), IssueTokenRequestError> {
        let nonce: Nonce = OsRng.r#gen();

        Self::issue_token_request_internal(public_key, challenge, nonce, None)
    }

    /// Issue a token request.
    fn issue_token_request_internal(
        public_key: PublicKey,
        challenge: &TokenChallenge,
        nonce: Nonce,
        _blind: Option<<NistP384 as voprf::Group>::Scalar>,
    ) -> Result<(TokenRequest, TokenState), IssueTokenRequestError> {
        let challenge_digest = challenge
            .digest()
            .map_err(|_| IssueTokenRequestError::InvalidTokenChallenge)?;

        let token_key_id = public_key_to_token_key_id(&public_key);

        // nonce = random(32)
        // challenge_digest = SHA256(challenge)
        // token_input = concat(0x0001, nonce, challenge_digest, token_key_id)
        // blind, blinded_element = client_context.Blind(token_input)

        let token_input = TokenInput::new(
            TokenType::PrivateToken,
            nonce,
            challenge_digest,
            token_key_id,
        );

        let blinded_element = VoprfClient::<NistP384>::blind(&token_input.serialize(), &mut OsRng)
            .map_err(|_| IssueTokenRequestError::BlindingError)?;

        #[cfg(feature = "kat")]
        let blinded_element = if let Some(blind) = _blind {
            VoprfClient::<NistP384>::deterministic_blind_unchecked(&token_input.serialize(), blind)
                .map_err(|_| IssueTokenRequestError::BlindingError)?
        } else {
            blinded_element
        };

        let token_request = TokenRequest {
            token_type: TokenType::PrivateToken,
            truncated_token_key_id: truncate_token_key_id(&token_key_id),
            blinded_msg: blinded_element.message.serialize().into(),
        };
        let token_state = TokenState {
            client: blinded_element.state,
            token_input,
            challenge_digest,
            public_key,
        };
        Ok((token_request, token_state))
    }

    #[cfg(feature = "kat")]
    /// Issue a token request.
    pub fn issue_token_request_with_params(
        public_key: PublicKey,
        challenge: &TokenChallenge,
        nonce: Nonce,
        blind: <NistP384 as voprf::Group>::Scalar,
    ) -> Result<(TokenRequest, TokenState), IssueTokenRequestError> {
        Self::issue_token_request_internal(public_key, challenge, nonce, Some(blind))
    }
}

impl TokenResponse {
    /// Issue a token.
    ///
    /// # Errors
    /// Returns an error if the response is invalid.
    pub fn issue_token(self, token_state: &TokenState) -> Result<PrivateToken, IssueTokenError> {
        let evaluation_element = EvaluationElement::deserialize(&self.evaluate_msg)
            .map_err(|_| IssueTokenError::InvalidTokenResponse)?;
        let proof = Proof::deserialize(&self.evaluate_proof)
            .map_err(|_| IssueTokenError::InvalidTokenResponse)?;
        let token_input = token_state.token_input.serialize();
        // authenticator = client_context.Finalize(token_input, blind, evaluated_element, blinded_element, proof)
        let authenticator = token_state
            .client
            .finalize(
                &token_input,
                &evaluation_element,
                &proof,
                token_state.public_key,
            )
            .map_err(|_| IssueTokenError::InvalidTokenResponse)?;

        Ok(Token::new(
            TokenType::PrivateToken,
            token_state.token_input.nonce,
            token_state.challenge_digest,
            token_state.token_input.token_key_id,
            authenticator,
        ))
    }
}
