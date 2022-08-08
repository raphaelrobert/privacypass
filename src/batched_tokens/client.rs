use rand::{rngs::OsRng, Rng};
use sha2::digest::OutputSizeUser;
use thiserror::*;
use voprf::*;

use crate::{
    auth::{authenticate::TokenChallenge, authorize::Token},
    ChallengeDigest, TokenType,
};

use super::{BlindedElement, Nonce, TokenInput, TokenRequest, TokenResponse};

pub struct TokenState {
    client: VoprfClient<Ristretto255>,
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
    public_key: <Ristretto255 as Group>::Elem,
}

impl Client {
    pub fn new(key_id: u8, public_key: <Ristretto255 as Group>::Elem) -> Self {
        Self {
            rng: OsRng,
            key_id,
            public_key,
        }
    }

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
            // token_input = concat(0x0003, nonce, challenge_digest, key_id)
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
                blinded_element: blind.message.serialize().to_vec(),
            };

            blinded_elements.push(blinded_element);
            token_states.push(token_state);
        }

        let token_request = TokenRequest {
            token_type: TokenType::Batched,
            token_key_id: self.key_id,
            blinded_elements,
        };

        Ok((token_request, token_states))
    }

    pub fn issue_token(
        &self,
        token_response: TokenResponse,
        token_states: Vec<TokenState>,
    ) -> Result<
        Vec<Token<<<Ristretto255 as CipherSuite>::Hash as OutputSizeUser>::OutputSize>>,
        IssueTokenError,
    > {
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
                .map(|token_state| token_state.token_input.serialize().to_vec())
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
