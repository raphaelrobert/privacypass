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

use super::{Nonce, Token, TokenInput, TokenRequest, TokenResponse, TokenState};

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
        challenge: &[u8],
    ) -> Result<(TokenRequest, TokenState<CS>), IssueTokenRequestError> {
        let nonce: Nonce = self.rng.gen();
        let context = Sha256::digest(challenge).to_vec();

        // nonce = random(32)
        // context = SHA256(challenge)
        // token_input = concat(0x0001, nonce, context, key_id)
        // blind, blinded_element = client_context.Blind(token_input)

        let token_input = TokenInput::new(1, nonce, context.clone(), self.key_id);

        let blinded_element = VoprfClient::<CS>::blind(&token_input.serialize(), &mut self.rng)
            .map_err(|_| IssueTokenRequestError::BlindingError)?;
        let token_request = TokenRequest {
            token_type: 1,
            token_key_id: 1,
            blinded_msg: blinded_element.message.serialize().to_vec(),
        };
        let token_state = TokenState {
            client: blinded_element.state,
            token_input,
            challenge_digest: context,
        };
        Ok((token_request, token_state))
    }

    pub fn issue_token(
        &self,
        token_response: TokenResponse,
        token_state: TokenState<CS>,
    ) -> Result<Token, IssueTokenError>
    where
        <CS::Hash as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    {
        let evaluation_element = EvaluationElement::deserialize(&token_response.evaluate_msg)
            .map_err(|_| IssueTokenError::InvalidTokenResponse)?;
        let proof = Proof::deserialize(&token_response.evaluate_proof)
            .map_err(|_| IssueTokenError::InvalidTokenResponse)?;
        let token_input = token_state.token_input.serialize();
        // authenticator = client_context.Finalize(token_input, blind, evaluated_element, blinded_element, proof)
        let authenticator = token_state
            .client
            .finalize(&token_input, &evaluation_element, &proof, self.public_key)
            .map_err(|_| IssueTokenError::InvalidTokenResponse)?
            .to_vec();
        Ok(Token {
            token_type: 1,
            nonce: token_state.token_input.nonce.to_vec(),
            challenge_digest: token_state.challenge_digest,
            token_key_id: token_state.token_input.key_id,
            authenticator,
        })
    }
}
