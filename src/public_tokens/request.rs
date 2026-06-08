//! Request implementation of the Publicly Verifiable Token protocol.

use blind_rsa_signatures::reexports::rand::CryptoRng;
use blind_rsa_signatures::{BlindingResult, pbrsa::PartiallyBlindPublicKey};
use log::warn;

use super::PublicKey;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::public_tokens::server::PbrsaPublicKey;
use crate::{
    ChallengeDigest, Nonce, TokenInput, TokenType, auth::authenticate::TokenChallenge,
    common::errors::IssueTokenRequestError, public_tokens::TokenProtocol, truncate_token_key_id,
};

use super::{NK, public_key_to_token_key_id};

/// State that is kept between the token requests and token responses.
#[derive(Debug)]
pub struct TokenState {
    pub(crate) token_input: TokenInput,
    pub(crate) challenge_digest: ChallengeDigest,
    pub(crate) blinding_result: BlindingResult,
    pub(crate) public_key: PublicKey,
    pub(crate) metadata: Option<Vec<u8>>,
    pub(crate) derived_pk: Option<PbrsaPublicKey>,
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
    /// Issue a new token request using the given protocol.
    ///
    /// # Errors
    /// Returns an error if the challenge is invalid or if blinding the token input fails.
    pub fn new_with_protocol<R: CryptoRng>(
        rng: &mut R,
        public_key: PublicKey,
        challenge: &TokenChallenge,
        protocol: TokenProtocol,
    ) -> Result<(TokenRequest, TokenState), IssueTokenRequestError> {
        let mut nonce: Nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);

        let challenge_digest = challenge
            .digest()
            .inspect_err(|e| warn!(error:% = e; "Failed to create challenge digest"))
            .map_err(|source| IssueTokenRequestError::InvalidTokenChallenge { source })?;

        let token_key_id = public_key_to_token_key_id(&public_key).map_err(|source| {
            IssueTokenRequestError::BlindingError {
                source: source.into(),
            }
        })?;

        let token_input =
            TokenInput::new(protocol.token_type(), nonce, challenge_digest, token_key_id);

        // nonce = random(32)
        // challenge_digest = SHA256(challenge)
        // token_input = concat(0x0002, nonce, challenge_digest, token_key_id)
        // blinded_msg, blind_inv = rsabssa_blind(pkI, token_input)

        let mut m: Option<_> = None;
        let mut dpk: Option<_> = None;

        let blinding_result = match protocol {
            TokenProtocol::Basic => public_key
                .blind(rng, token_input.serialize())
                .inspect_err(|e| warn!(error:% = e; "Failed to blind token input"))
                .map_err(|source| IssueTokenRequestError::BlindingError {
                    source: source.into(),
                })?,
            TokenProtocol::PublicMetadata { metadata } => {
                let pbrsa_pk: PbrsaPublicKey =
                    PartiallyBlindPublicKey::new(public_key.as_ref().clone());
                let derived_pk = pbrsa_pk
                    .derive_public_key_for_metadata(metadata)
                    .inspect_err(|e| warn!(error:% = e; "Failed to derive metadata public key"))
                    .map_err(|source| IssueTokenRequestError::BlindingError {
                        source: source.into(),
                    })?;

                let result = derived_pk
                    .blind(rng, token_input.serialize(), Some(metadata))
                    .inspect_err(|e| warn!(error:% = e; "Failed to blind token input"))
                    .map_err(|source| IssueTokenRequestError::BlindingError {
                        source: source.into(),
                    })?;

                m = Some(metadata.to_vec());
                dpk = Some(derived_pk);

                result
            }
        };

        debug_assert!(blinding_result.blind_message.len() == NK);
        let mut blinded_msg = [0u8; NK];
        blinded_msg.copy_from_slice(blinding_result.blind_message.as_slice());

        let token_request = TokenRequest {
            token_type: protocol.token_type(),
            truncated_token_key_id: truncate_token_key_id(&token_key_id),
            blinded_msg,
        };

        let token_state = TokenState {
            blinding_result,
            token_input,
            challenge_digest,
            public_key,
            metadata: m,
            derived_pk: dpk,
        };
        Ok((token_request, token_state))
    }

    /// Issue a new token request.
    ///
    /// # Errors
    /// Returns an error if the challenge is invalid.
    pub fn new<R: CryptoRng>(
        rng: &mut R,
        public_key: PublicKey,
        challenge: &TokenChallenge,
    ) -> Result<(TokenRequest, TokenState), IssueTokenRequestError> {
        Self::new_with_protocol(rng, public_key, challenge, TokenProtocol::Basic)
    }
}
