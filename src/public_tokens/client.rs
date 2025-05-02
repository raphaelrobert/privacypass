//! Client-side implementation of the Privately Verifiable Token protocol.

use blind_rsa_signatures::{BlindSignature, BlindingResult, Options, PublicKey};
use generic_array::{GenericArray, typenum::U256};
use rand::{CryptoRng, RngCore};

use crate::{
    ChallengeDigest, TokenInput, TokenType,
    auth::{authenticate::TokenChallenge, authorize::Token},
    common::errors::{IssueTokenError, IssueTokenRequestError},
};

use super::{
    NK, Nonce, PublicToken, TokenRequest, TokenResponse, public_key_to_token_key_id,
    truncate_token_key_id,
};

/// Client-side state that is kept between the token requests and token responses.
#[derive(Debug)]
pub struct TokenState {
    token_input: TokenInput,
    challenge_digest: ChallengeDigest,
    blinding_result: BlindingResult,
    public_key: PublicKey,
}

impl TokenRequest {
    /// Issue a new token request.
    ///
    /// # Errors
    /// Returns an error if the challenge is invalid.
    pub fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        public_key: PublicKey,
        challenge: &TokenChallenge,
    ) -> Result<(TokenRequest, TokenState), IssueTokenRequestError> {
        let mut nonce: Nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);

        let challenge_digest = challenge
            .digest()
            .map_err(|_| IssueTokenRequestError::InvalidTokenChallenge)?;

        let token_key_id = public_key_to_token_key_id(&public_key);

        // nonce = random(32)
        // challenge_digest = SHA256(challenge)
        // token_input = concat(0x0002, nonce, challenge_digest, token_key_id)
        // blinded_msg, blind_inv = rsabssa_blind(pkI, token_input)

        let token_input = TokenInput::new(TokenType::Public, nonce, challenge_digest, token_key_id);

        let options = Options::default();
        let blinding_result = public_key
            .blind(rng, token_input.serialize(), false, &options)
            .map_err(|_| IssueTokenRequestError::BlindingError)?;

        debug_assert!(blinding_result.blind_msg.len() == NK);
        let mut blinded_msg = [0u8; NK];
        blinded_msg.copy_from_slice(blinding_result.blind_msg.as_slice());

        let token_request = TokenRequest {
            token_type: TokenType::Public,
            truncated_token_key_id: truncate_token_key_id(&token_key_id),
            blinded_msg,
        };

        let token_state = TokenState {
            blinding_result,
            token_input,
            challenge_digest,
            public_key,
        };
        Ok((token_request, token_state))
    }
}

impl TokenResponse {
    /// Issue a token.
    ///
    /// # Errors
    /// Returns an error if the token response is invalid.
    pub fn issue_token(self, token_state: &TokenState) -> Result<PublicToken, IssueTokenError> {
        // authenticator = rsabssa_finalize(pkI, nonce, blind_sig, blind_inv)
        let token_input = token_state.token_input.serialize();
        let options = Options::default();
        let blind_sig = BlindSignature(self.blind_sig.to_vec());
        let signature = token_state
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
            token_state.token_input.token_key_id,
            authenticator,
        ))
    }
}
