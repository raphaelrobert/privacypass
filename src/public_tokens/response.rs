//! Response implementation of the Publicly Verifiable Token protocol.

use blind_rsa_signatures::BlindSignature;
use hybrid_array::{Array, typenum::U256};
use log::warn;
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::{TokenType, auth::authorize::Token, common::errors::IssueTokenError};

use super::{NK, PublicToken, TokenState, request::TokenStateInner};

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
        let blind_sig = BlindSignature(self.blind_sig.to_vec());

        let (token_type, token_input, signature) = match &token_state.inner {
            TokenStateInner::Public {
                token_input,
                blinding_result,
                public_key,
            } => (
                TokenType::Public,
                token_input,
                public_key
                    .finalize(&blind_sig, blinding_result, token_input.serialize())
                    .inspect_err(|e| warn!(error:% = e; "Failed to finalize blind signature"))
                    .map_err(|source| IssueTokenError::SignatureFinalizationFailed {
                        token_type: TokenType::Public,
                        source,
                    })?,
            ),
            TokenStateInner::PublicMetadata {
                token_input,
                blinding_result,
                metadata,
                public_key,
            } => (
                TokenType::PublicMetadata,
                token_input,
                public_key
                    .finalize(
                        &blind_sig,
                        blinding_result,
                        token_input.serialize(),
                        Some(metadata),
                    )
                    .inspect_err(|e| warn!(error:% = e; "Failed to finalize blind signature"))
                    .map_err(|source| IssueTokenError::SignatureFinalizationFailed {
                        token_type: TokenType::PublicMetadata,
                        source,
                    })?,
            ),
        };

        let mut authenticator = Array::<u8, U256>::default();
        authenticator.copy_from_slice(&signature[0..256]);
        Ok(Token::new(
            token_type,
            token_input.nonce,
            token_input.challenge_digest,
            token_input.token_key_id,
            authenticator,
        ))
    }
}
