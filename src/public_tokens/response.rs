//! Response implementation of the Publicly Verifiable Token protocol.

use blind_rsa_signatures::{BlindSignature, Options};
use generic_array::{GenericArray, typenum::U256};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::{TokenType, auth::authorize::Token, common::errors::IssueTokenError};

use super::{NK, PublicToken, TokenState};

/// Token response as specified in the spec:
///
/// ```c
/// struct {
///     uint8_t blind_sig[Nk];
///  } TokenResponse;
/// ```
#[derive(Debug, Clone, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct TokenResponse {
    pub(crate) blind_sig: [u8; NK],
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
