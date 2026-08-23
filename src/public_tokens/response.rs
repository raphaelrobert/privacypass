//! Response implementation of the Publicly Verifiable Token protocol.

use blind_rsa_signatures::BlindSignature;
use generic_array::{GenericArray, typenum::U256};
use log::warn;
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

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
        let token_type = token_state.token_input.token_type;
        let blind_sig = BlindSignature(self.blind_sig.to_vec());

        let signature = match token_type {
            TokenType::Public => token_state
                .public_key
                .finalize(&blind_sig, &token_state.blinding_result, token_input)
                .inspect_err(|e| warn!(error:% = e; "Failed to finalize blind signature"))
                .map_err(|source| IssueTokenError::SignatureFinalizationFailed {
                    token_type,
                    source,
                })?,
            TokenType::PublicMetadata => {
                let (metadata, derived_pk) = token_state
                    .pbrsa_state
                    .as_ref()
                    .ok_or(IssueTokenError::NoPbrsaState)
                    .inspect_err(|e| warn!(error:% = e; "No PBRSA state found"))?;

                derived_pk
                    .finalize(
                        &blind_sig,
                        &token_state.blinding_result,
                        token_input,
                        Some(metadata),
                    )
                    .inspect_err(|e| warn!(error:% = e; "Failed to finalize blind signature"))
                    .map_err(|source| IssueTokenError::SignatureFinalizationFailed {
                        token_type,
                        source,
                    })?
            }
            _ => return Err(IssueTokenError::InvalidTokenType { token_type }),
        };

        let authenticator: GenericArray<u8, U256> = *GenericArray::from_slice(&signature[0..256]);
        Ok(Token::new(
            token_type,
            token_state.token_input.nonce,
            token_state.challenge_digest,
            token_state.token_input.token_key_id,
            authenticator,
        ))
    }
}
