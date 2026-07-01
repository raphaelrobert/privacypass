//! Request implementation of the Publicly Verifiable Token protocol.

use std::io::{Read, Write};

use blind_rsa_signatures::reexports::rand::CryptoRng;
use blind_rsa_signatures::{BlindingResult, pbrsa::PartiallyBlindPublicKey};
use log::warn;
use tls_codec::{Deserialize, Serialize, Size};

use super::PublicKey;

use crate::common::extensions::Extensions;
use crate::public_tokens::server::PbrsaPublicKey;
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
    pub(crate) pbrsa_state: Option<(Vec<u8>, PbrsaPublicKey)>,
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
///
/// or, if created with extensions:
/// ```c
/// struct {
///     TokenRequest request;
///     Extensions extensions;
/// } ExtendedTokenRequest;
/// ```
/// As specified in
/// [`draft-ietf-privacypass-public-metadata-issuance-03 §6.1`](https://www.ietf.org/archive/id/draft-ietf-privacypass-public-metadata-issuance-03.html#section-6.1).
#[derive(Debug, Clone, PartialEq)]
pub struct TokenRequest {
    pub(crate) token_type: TokenType,
    pub(crate) truncated_token_key_id: u8,
    pub(crate) blinded_msg: [u8; NK],
    pub(crate) extensions: Option<Extensions>,
}

impl TokenRequest {
    /// Get the extensions associated with this request, if any.
    ///
    /// This is useful for validating the extensions before signing, e.g. for checking an
    /// expiration date etc.
    pub fn extensions(&self) -> &Option<Extensions> {
        &self.extensions
    }
}

// We have to implement these manually in order to avoid having the Option<T> serialization byte
impl Size for TokenRequest {
    fn tls_serialized_len(&self) -> usize {
        self.token_type.tls_serialized_len()
            + self.truncated_token_key_id.tls_serialized_len()
            + self.blinded_msg.tls_serialized_len()
            + match &self.extensions {
                Some(e) => e.tls_serialized_len(),
                None => 0,
            }
    }
}

impl Serialize for TokenRequest {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = 0;
        written += self.token_type.tls_serialize(writer)?;
        written += self.truncated_token_key_id.tls_serialize(writer)?;
        written += self.blinded_msg.tls_serialize(writer)?;
        if let Some(extensions) = &self.extensions {
            written += extensions.tls_serialize(writer)?;
        }

        Ok(written)
    }
}

impl Deserialize for TokenRequest {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let token_type = TokenType::tls_deserialize(bytes)?;
        let truncated_token_key_id = u8::tls_deserialize(bytes)?;
        let blinded_msg = <[u8; NK]>::tls_deserialize(bytes)?;

        let extensions = if token_type == TokenType::PublicMetadata {
            Some(Extensions::tls_deserialize(bytes)?)
        } else {
            None
        };

        Ok(Self {
            token_type,
            truncated_token_key_id,
            blinded_msg,
            extensions,
        })
    }
}

impl TokenRequest {
    /// Issue a new token request.
    ///
    /// # Errors
    /// Returns an error if the challenge is invalid.
    pub fn new<R: CryptoRng>(
        rng: &mut R,
        public_key: PublicKey,
        challenge: &TokenChallenge,
    ) -> Result<(TokenRequest, TokenState), IssueTokenRequestError> {
        if challenge.token_type != TokenType::Public {
            return Err(IssueTokenRequestError::InvalidTokenType {
                expected: TokenType::Public,
                found: challenge.token_type,
            });
        }

        Self::new_maybe_extensions(rng, public_key, challenge, None)
    }

    /// Issue a new token request using the given extensions
    ///
    /// # Errors
    /// Returns an error if the challenge is invalid or if blinding the token input fails.
    pub fn new_with_extensions<R: CryptoRng>(
        rng: &mut R,
        public_key: PublicKey,
        challenge: &TokenChallenge,
        extensions: Extensions,
    ) -> Result<(TokenRequest, TokenState), IssueTokenRequestError> {
        if challenge.token_type != TokenType::PublicMetadata {
            return Err(IssueTokenRequestError::InvalidTokenType {
                expected: TokenType::PublicMetadata,
                found: challenge.token_type,
            });
        }

        Self::new_maybe_extensions(rng, public_key, challenge, Some(extensions))
    }

    fn new_maybe_extensions<R: CryptoRng>(
        rng: &mut R,
        public_key: PublicKey,
        challenge: &TokenChallenge,
        extensions: Option<Extensions>,
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

        let token_type = if extensions.is_some() {
            TokenType::PublicMetadata
        } else {
            TokenType::Public
        };

        let token_input = TokenInput::new(token_type, nonce, challenge_digest, token_key_id);

        // nonce = random(32)
        // challenge_digest = SHA256(challenge)
        // token_input = concat(0x0002, nonce, challenge_digest, token_key_id)
        // blinded_msg, blind_inv = rsabssa_blind(pkI, token_input)

        let (blinding_result, pbrsa_state) = if let Some(ref extensions) = extensions {
            let metadata = extensions
                .tls_serialize_detached()
                .inspect_err(|e| warn!(error:% = e; "Failed to serialize extensions"))
                .map_err(|source| IssueTokenRequestError::ExtensionSerializationError { source })?;

            let pbrsa_pk: PbrsaPublicKey =
                PartiallyBlindPublicKey::new(public_key.as_ref().clone());
            let derived_pk = pbrsa_pk
                .derive_public_key_for_metadata(&metadata)
                .inspect_err(|e| warn!(error:% = e; "Failed to derive metadata public key"))
                .map_err(|source| IssueTokenRequestError::BlindingError {
                    source: source.into(),
                })?;

            let blinding_result = derived_pk
                .blind(rng, token_input.serialize(), Some(&metadata))
                .inspect_err(|e| warn!(error:% = e; "Failed to blind token input"))
                .map_err(|source| IssueTokenRequestError::BlindingError {
                    source: source.into(),
                })?;

            let pbrsa_state = Some((metadata, derived_pk));

            (blinding_result, pbrsa_state)
        } else {
            let blinding_result = public_key
                .blind(rng, token_input.serialize())
                .inspect_err(|e| warn!(error:% = e; "Failed to blind token input"))
                .map_err(|source| IssueTokenRequestError::BlindingError {
                    source: source.into(),
                })?;

            (blinding_result, None)
        };

        debug_assert!(blinding_result.blind_message.len() == NK);
        let mut blinded_msg = [0u8; NK];
        blinded_msg.copy_from_slice(blinding_result.blind_message.as_slice());

        let token_request = TokenRequest {
            token_type,
            truncated_token_key_id: truncate_token_key_id(&token_key_id),
            blinded_msg,
            extensions,
        };

        let token_state = TokenState {
            blinding_result,
            token_input,
            challenge_digest,
            public_key,
            pbrsa_state,
        };

        Ok((token_request, token_state))
    }
}
