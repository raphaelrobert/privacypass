//! Client-side implementation of the Privately Verifiable Token protocol.

use p384::NistP384;
use rand::{rngs::OsRng, Rng};
use thiserror::Error;
use voprf::{EvaluationElement, Proof, Result, VoprfClient};

use crate::{
    auth::{authenticate::TokenChallenge, authorize::Token},
    ChallengeDigest, KeyId, TokenInput, TokenType,
};

use super::{
    key_id_to_token_key_id, public_key_to_key_id, Nonce, PrivateToken, PublicKey, TokenRequest,
    TokenResponse,
};

/// Client-side state that is kept between the token requests and token responses.
#[derive(Debug)]
pub struct TokenState {
    token_input: TokenInput,
    challenge_digest: ChallengeDigest,
    client: VoprfClient<NistP384>,
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

/// The client side of the Privately Verifiable Token protocol.
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
    /// Returns an error if the challenge is invalid.
    pub fn issue_token_request(
        &mut self,
        challenge: &TokenChallenge,
    ) -> Result<(TokenRequest, TokenState), IssueTokenRequestError> {
        let nonce: Nonce = self.rng.gen();

        let challenge_digest = challenge
            .digest()
            .map_err(|_| IssueTokenRequestError::InvalidTokenChallenge)?;

        // nonce = random(32)
        // challenge_digest = SHA256(challenge)
        // token_input = concat(0x0001, nonce, challenge_digest, key_id)
        // blind, blinded_element = client_context.Blind(token_input)

        let token_input = TokenInput::new(TokenType::Private, nonce, challenge_digest, self.key_id);

        let blinded_element =
            VoprfClient::<NistP384>::blind(&token_input.serialize(), &mut self.rng)
                .map_err(|_| IssueTokenRequestError::BlindingError)?;
        let token_request = TokenRequest {
            token_type: TokenType::Private,
            token_key_id: key_id_to_token_key_id(&self.key_id),
            blinded_msg: blinded_element.message.serialize().into(),
        };
        let token_state = TokenState {
            client: blinded_element.state,
            token_input,
            challenge_digest,
        };
        Ok((token_request, token_state))
    }

    #[cfg(feature = "kat")]
    /// Issue a token request.
    pub fn issue_token_request_with_params(
        &mut self,
        challenge: &TokenChallenge,
        nonce: Nonce,
        blind: <NistP384 as voprf::Group>::Scalar,
    ) -> Result<(TokenRequest, TokenState), IssueTokenRequestError> {
        let challenge_digest = challenge
            .digest()
            .map_err(|_| IssueTokenRequestError::InvalidTokenChallenge)?;

        // nonce = random(32)
        // challenge_digest = SHA256(challenge)
        // token_input = concat(0x0001, nonce, challenge_digest, key_id)
        // blind, blinded_element = client_context.Blind(token_input)

        let token_input = TokenInput::new(TokenType::Private, nonce, challenge_digest, self.key_id);

        let blinded_element =
            VoprfClient::<NistP384>::deterministic_blind_unchecked(&token_input.serialize(), blind)
                .map_err(|_| IssueTokenRequestError::BlindingError)?;
        let token_request = TokenRequest {
            token_type: TokenType::Private,
            token_key_id: key_id_to_token_key_id(&self.key_id),
            blinded_msg: blinded_element.message.serialize().into(),
        };
        let token_state = TokenState {
            client: blinded_element.state,
            token_input,
            challenge_digest,
        };
        Ok((token_request, token_state))
    }

    /// Issue a token.
    ///
    /// # Errors
    /// Returns an error if the response is invalid.
    pub fn issue_token(
        &self,
        token_response: &TokenResponse,
        token_state: &TokenState,
    ) -> Result<PrivateToken, IssueTokenError> {
        let evaluation_element = EvaluationElement::deserialize(&token_response.evaluate_msg)
            .map_err(|_| IssueTokenError::InvalidTokenResponse)?;
        let proof = Proof::deserialize(&token_response.evaluate_proof)
            .map_err(|_| IssueTokenError::InvalidTokenResponse)?;
        let token_input = token_state.token_input.serialize();
        // authenticator = client_context.Finalize(token_input, blind, evaluated_element, blinded_element, proof)
        let authenticator = token_state
            .client
            .finalize(&token_input, &evaluation_element, &proof, self.public_key)
            .map_err(|_| IssueTokenError::InvalidTokenResponse)?;

        Ok(Token::new(
            TokenType::Private,
            token_state.token_input.nonce,
            token_state.challenge_digest,
            token_state.token_input.key_id,
            authenticator,
        ))
    }
}
