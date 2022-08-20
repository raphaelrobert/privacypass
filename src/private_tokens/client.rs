use p256::NistP256;
use rand::{rngs::OsRng, Rng};
use thiserror::*;
use voprf::*;

use crate::{
    auth::{authenticate::TokenChallenge, authorize::Token},
    ChallengeDigest, TokenInput, TokenType,
};

use super::{Nonce, PrivateToken, PublicKey, TokenRequest, TokenResponse};

pub struct TokenState {
    client: VoprfClient<NistP256>,
    token_input: TokenInput,
    challenge_digest: ChallengeDigest,
}

#[derive(Error, Debug, PartialEq)]
pub enum IssueTokenRequestError {
    #[error("Token blinding error")]
    BlindingError,
    #[error("Invalid TokenChallenge")]
    InvalidTokenChallenge,
}

#[derive(Error, Debug, PartialEq)]
pub enum IssueTokenError {
    #[error("Invalid TokenResponse")]
    InvalidTokenResponse,
}

pub struct Client {
    rng: OsRng,
    key_id: u8,
    public_key: PublicKey,
}

impl Client {
    pub fn new(key_id: u8, public_key: PublicKey) -> Self {
        Self {
            rng: OsRng,
            key_id,
            public_key,
        }
    }

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
            VoprfClient::<NistP256>::blind(&token_input.serialize(), &mut self.rng)
                .map_err(|_| IssueTokenRequestError::BlindingError)?;
        let token_request = TokenRequest {
            token_type: TokenType::Private,
            token_key_id: self.key_id,
            blinded_msg: blinded_element.message.serialize().into(),
        };
        let token_state = TokenState {
            client: blinded_element.state,
            token_input,
            challenge_digest,
        };
        Ok((token_request, token_state))
    }

    pub fn issue_token(
        &self,
        token_response: TokenResponse,
        token_state: TokenState,
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
