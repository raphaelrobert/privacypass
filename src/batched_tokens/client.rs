use rand::{rngs::OsRng, Rng};
use sha2::{
    digest::{
        core_api::BlockSizeUser,
        typenum::{IsLess, IsLessOrEqual, U256},
        OutputSizeUser,
    },
    Digest, Sha256,
};
use thiserror::*;
use voprf::*;

use crate::{auth::TokenChallenge, TokenType};

use super::{BlindedElement, Nonce, Token, TokenInput, TokenRequest, TokenResponse};

pub struct TokenState<CS: CipherSuite>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    client: VoprfClient<CS>,
    token_input: TokenInput,
    challenge_digest: Vec<u8>,
}

#[derive(Error, Debug, PartialEq)]
pub enum IssueTokenRequestError {
    #[error("Token blinding error")]
    BlindingError,
}

#[derive(Error, Debug, PartialEq)]
pub enum IssueTokenError {
    #[error("Invalid TokenResponse")]
    InvalidTokenResponse,
}

pub struct Client<CS: CipherSuite>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    rng: OsRng,
    key_id: u8,
    public_key: <CS::Group as Group>::Elem,
}

impl<CS: CipherSuite> Client<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    pub fn new(key_id: u8, public_key: <CS::Group as Group>::Elem) -> Self {
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
    ) -> Result<(TokenRequest, Vec<TokenState<CS>>), IssueTokenRequestError> {
        let challenge_digest = Sha256::digest(challenge.serialize()).to_vec();
        let mut blinded_elements = Vec::new();
        let mut token_states = Vec::new();

        for _ in 0..nr {
            // nonce = random(32)
            // context = SHA256(challenge)
            // token_input = concat(0x0003, nonce, context, key_id)
            // blind, blinded_element = client_context.Blind(token_input)

            let nonce: Nonce = self.rng.gen();

            let token_input = TokenInput::new(
                TokenType::Batched,
                nonce,
                challenge_digest.clone(),
                self.key_id,
            );

            let blind = VoprfClient::<CS>::blind(&token_input.serialize(), &mut self.rng)
                .map_err(|_| IssueTokenRequestError::BlindingError)?;

            let token_state = TokenState {
                client: blind.state,
                token_input,
                challenge_digest: challenge_digest.clone(),
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
        token_states: Vec<TokenState<CS>>,
    ) -> Result<Vec<Token>, IssueTokenError>
    where
        <CS::Hash as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    {
        let mut evaluated_elements = Vec::new();
        for element in token_response.evaluated_elements.iter() {
            let evaluated_element =
                EvaluationElement::<CS>::deserialize(&element.evaluated_element)
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
            let token = Token {
                token_type: TokenType::Batched,
                nonce: token_state.token_input.nonce,
                challenge_digest: token_state.challenge_digest.clone(),
                token_key_id: token_state.token_input.key_id,
                authenticator: authenticator.to_vec(),
            };
            tokens.push(token);
        }

        Ok(tokens)
    }
}
