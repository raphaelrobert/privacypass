//! Client-side implementation of the Privately Verifiable Token protocol.

use blind_rsa_signatures::{BlindSignature, BlindingResult, Options, PublicKey};
use generic_array::{typenum::U256, GenericArray};
use rand::{CryptoRng, RngCore};
use thiserror::Error;

use crate::{
    auth::{authenticate::TokenChallenge, authorize::Token},
    ChallengeDigest, KeyId, TokenInput, TokenType,
};

use super::{key_id_to_token_key_id, public_key_to_key_id, Nonce, TokenRequest, TokenResponse, NK};

/// Client-side state that is kept between the token requests and token responses.
#[derive(Debug)]
pub struct TokenState {
    blinding_result: BlindingResult,
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

/// The client side of the Publicly Verifiable Token protocol.
#[derive(Debug)]
pub struct Client {
    key_id: KeyId,
    public_key: PublicKey,
}

impl Client {
    /// Create a new client from a public key.
    #[must_use]
    pub fn new(public_key: PublicKey) -> Self {
        let key_id = public_key_to_key_id(&public_key);

        Self { key_id, public_key }
    }

    /// Issue a token request.
    ///
    /// # Errors
    /// Returns an error if the challenge is invalid.
    pub fn issue_token_request<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        challenge: TokenChallenge,
    ) -> Result<(TokenRequest, TokenState), IssueTokenRequestError> {
        let mut nonce: Nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce[..]);

        let challenge_digest = challenge
            .digest()
            .map_err(|_| IssueTokenRequestError::InvalidTokenChallenge)?;

        // nonce = random(32)
        // challenge_digest = SHA256(challenge)
        // token_input = concat(0x0002, nonce, challenge_digest, token_key_id)
        // blinded_msg, blind_inv = rsabssa_blind(pkI, token_input)

        let token_input = TokenInput::new(TokenType::Public, nonce, challenge_digest, self.key_id);

        let options = Options::default();
        let blinding_result = self
            .public_key
            .blind(rng, token_input.serialize(), false, &options)
            .map_err(|_| IssueTokenRequestError::BlindingError)?;

        debug_assert!(blinding_result.blind_msg.len() == NK);
        let mut blinded_msg = [0u8; NK];
        blinded_msg.copy_from_slice(blinding_result.blind_msg.as_slice());

        let token_request = TokenRequest {
            token_type: TokenType::Public,
            token_key_id: key_id_to_token_key_id(&self.key_id),
            blinded_msg,
        };

        let token_state = TokenState {
            blinding_result,
            token_input,
            challenge_digest,
        };
        Ok((token_request, token_state))
    }

    /// Issue a token.
    ///
    /// # Errors
    /// Returns an error if the token response is invalid.
    pub fn issue_token(
        &self,
        token_response: TokenResponse,
        token_state: &TokenState,
    ) -> Result<Token<U256>, IssueTokenError> {
        // authenticator = rsabssa_finalize(pkI, nonce, blind_sig, blind_inv)
        let token_input = token_state.token_input.serialize();
        let options = Options::default();
        let blind_sig = BlindSignature(token_response.blind_sig.to_vec());
        let signature = self
            .public_key
            .finalize(
                &blind_sig,
                &token_state.blinding_result.secret,
                None,
                token_input,
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
