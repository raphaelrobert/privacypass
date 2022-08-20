use blind_rsa_signatures::{BlindSignature, BlindingResult, Options, PublicKey};
use generic_array::{typenum::U256, GenericArray};
use rand::{rngs::OsRng, Rng};
use thiserror::*;

use crate::{
    auth::{authenticate::TokenChallenge, authorize::Token},
    ChallengeDigest, TokenInput, TokenType,
};

use super::{Nonce, TokenRequest, TokenResponse};

pub struct TokenState {
    blinding_result: BlindingResult,
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
        // token_input = concat(0x0002, nonce, challenge_digest, key_id)
        // blinded_msg, blind_inv = rsabssa_blind(pkI, token_input)

        let token_input = TokenInput::new(TokenType::Public, nonce, challenge_digest, self.key_id);

        let options = Options::default();
        let blinding_result = self
            .public_key
            .blind(&token_input.serialize(), &options)
            .map_err(|_| IssueTokenRequestError::BlindingError)?;

        let token_request = TokenRequest {
            token_type: TokenType::Public,
            token_key_id: self.key_id,
            blinded_msg: blinding_result.blind_msg.to_vec(),
        };
        let token_state = TokenState {
            blinding_result,
            token_input,
            challenge_digest,
        };
        Ok((token_request, token_state))
    }

    pub fn issue_token(
        &self,
        token_response: TokenResponse,
        token_state: TokenState,
    ) -> Result<Token<U256>, IssueTokenError> {
        // authenticator = rsabssa_finalize(pkI, nonce, blind_sig, blind_inv)
        let token_input = token_state.token_input.serialize();
        let options = Options::default();
        let blind_sig = BlindSignature(token_response.blind_sig);
        let signature = self
            .public_key
            .finalize(
                &blind_sig,
                &token_state.blinding_result.secret,
                &token_input,
                &options,
            )
            .map_err(|_| IssueTokenError::InvalidTokenResponse)?;
        let authenticator: GenericArray<u8, U256> =
            GenericArray::clone_from_slice(&signature[0..256]);
        Ok(Token::new(
            TokenType::Public,
            token_state.token_input.nonce,
            token_state.challenge_digest,
            token_state.token_input.key_id,
            authenticator,
        ))
    }
}
