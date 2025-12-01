//! Request implementation of the Publicly Verifiable Token protocol.

use blind_rsa_signatures::{BlindingResult, Options, PublicKey};
use log::warn;
use rand::{CryptoRng, RngCore};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::{
    ChallengeDigest, Nonce, TokenInput, TokenType, auth::authenticate::TokenChallenge,
    common::errors::IssueTokenRequestError, truncate_token_key_id,
};

use super::{NK, public_key_to_token_key_id};

/// State that is kept between the token requests and token responses.
#[derive(Debug)]
pub struct TokenState {
    pub(crate) token_input: TokenInput,
    pub(crate) challenge_digest: ChallengeDigest,
    pub(crate) blinding_result: BlindingResult,
    pub(crate) public_key: PublicKey,
}

/// Token request as specified in the spec:
///
/// ```c
/// struct {
///     uint16_t token_type = 0x0002;
///     uint8_t truncated_token_key_id;
///     uint8_t blinded_msg[Nk];
///  } TokenRequest;
/// ```
#[derive(Debug, Clone, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct TokenRequest {
    pub(crate) token_type: TokenType,
    pub(crate) truncated_token_key_id: u8,
    pub(crate) blinded_msg: [u8; NK],
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
            .inspect_err(|e| warn!(error:% = e; "Failed to blind token input"))
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
