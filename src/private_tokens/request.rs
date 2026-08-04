//! Request implementation of the Privately Verifiable Token protocol.

use rand::{TryRng, rngs::SysRng};
use tls_codec::{Deserialize, Serialize, Size};
use typenum::Unsigned;
use voprf::{Group, Result, VoprfClient};

#[cfg(feature = "deterministic-issuance")]
use crate::common::{errors::DeterministicIssuanceError, private::Scalar};
use crate::{
    ChallengeDigest, Nonce, TokenInput, TokenType, TruncatedTokenKeyId,
    auth::authenticate::TokenChallenge,
    common::{
        errors::IssueTokenRequestError,
        private::{PrivateCipherSuite, PublicKey, public_key_to_token_key_id},
    },
    truncate_token_key_id,
};

/// Token request as specified in the spec:
///
/// ```c
/// struct {
///     uint16_t token_type = 0x0001;
///     uint8_t truncated_token_key_id;
///     uint8_t blinded_msg[Ne];
///  } TokenRequest;
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct TokenRequest<CS: PrivateCipherSuite> {
    pub(crate) _marker: std::marker::PhantomData<CS>,
    pub(crate) token_type: TokenType,
    pub(crate) truncated_token_key_id: u8,
    pub(crate) blinded_msg: Vec<u8>,
}

/// State that is kept between the token requests and token responses.
pub struct TokenState<CS: PrivateCipherSuite> {
    pub(crate) token_input: TokenInput,
    pub(crate) challenge_digest: ChallengeDigest,
    pub(crate) client: VoprfClient<CS>,
    pub(crate) public_key: PublicKey<CS>,
}

impl<CS: PrivateCipherSuite> std::fmt::Debug for TokenState<CS> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenState")
            .field("client", &"client".to_string())
            .field("token_input", &self.token_input)
            .field("challenge_digest", &self.challenge_digest)
            .field("public_key", &"public key".to_string())
            .finish()
    }
}

impl<CS: PrivateCipherSuite> TokenRequest<CS> {
    /// Issue a new token request.
    ///
    /// # Errors
    /// Returns an error if the challenge is invalid.
    pub fn new(
        public_key: PublicKey<CS>,
        challenge: &TokenChallenge,
    ) -> Result<(TokenRequest<CS>, TokenState<CS>), IssueTokenRequestError> {
        let mut nonce = Nonce::default();
        SysRng
            .try_fill_bytes(&mut nonce)
            .map_err(|source| IssueTokenRequestError::RngFailed { source })?;

        let challenge_digest = challenge
            .digest()
            .map_err(|source| IssueTokenRequestError::InvalidTokenChallenge { source })?;

        let token_key_id = public_key_to_token_key_id::<CS>(&public_key);

        // nonce = random(32)
        // challenge_digest = SHA256(challenge)
        // token_input = concat(0x0001, nonce, challenge_digest, token_key_id)
        // blind, blinded_element = client_context.Blind(token_input)

        let token_input = TokenInput::new(CS::token_type(), nonce, challenge_digest, token_key_id);

        let blinded_element = VoprfClient::<CS>::blind(&token_input.serialize(), &mut SysRng)
            .map_err(|source| IssueTokenRequestError::BlindingError {
                source: source.into(),
            })?;

        let token_request = TokenRequest {
            _marker: std::marker::PhantomData,
            token_type: CS::token_type(),
            truncated_token_key_id: truncate_token_key_id(&token_key_id),
            blinded_msg: blinded_element.message.serialize().to_vec(),
        };
        let token_state = TokenState {
            client: blinded_element.state,
            token_input,
            challenge_digest,
            public_key,
        };
        Ok((token_request, token_state))
    }

    /// Issue a token request from a caller-supplied blinding scalar.
    ///
    /// # Errors
    /// Returns [`DeterministicIssuanceError::ZeroBlind`] if the blinding scalar
    /// is zero. Challenge and blinding failures are wrapped transparently as
    /// [`IssueTokenRequestError`].
    #[cfg(feature = "deterministic-issuance")]
    pub fn issue_token_request_with_params(
        public_key: PublicKey<CS>,
        challenge: &TokenChallenge,
        nonce: Nonce,
        blind: Scalar<CS>,
    ) -> Result<(TokenRequest<CS>, TokenState<CS>), DeterministicIssuanceError> {
        if bool::from(CS::Group::is_zero_scalar(blind)) {
            return Err(DeterministicIssuanceError::ZeroBlind { index: 0 });
        }

        let challenge_digest = challenge
            .digest()
            .map_err(|source| IssueTokenRequestError::InvalidTokenChallenge { source })?;

        let token_key_id = public_key_to_token_key_id::<CS>(&public_key);

        let token_input = TokenInput::new(CS::token_type(), nonce, challenge_digest, token_key_id);

        let blinded_element =
            VoprfClient::<CS>::deterministic_blind_unchecked(&token_input.serialize(), blind)
                .map_err(|source| IssueTokenRequestError::BlindingError {
                    source: source.into(),
                })?;

        let token_request = TokenRequest {
            _marker: std::marker::PhantomData,
            token_type: CS::token_type(),
            truncated_token_key_id: truncate_token_key_id(&token_key_id),
            blinded_msg: blinded_element.message.serialize().to_vec(),
        };
        let token_state = TokenState {
            client: blinded_element.state,
            token_input,
            challenge_digest,
            public_key,
        };
        Ok((token_request, token_state))
    }
}

impl<CS: PrivateCipherSuite> Size for TokenRequest<CS> {
    fn tls_serialized_len(&self) -> usize {
        let len = <<CS::Group as Group>::ElemLen as Unsigned>::USIZE;
        self.token_type.tls_serialized_len()
            + self.truncated_token_key_id.tls_serialized_len()
            + len
    }
}

impl<CS: PrivateCipherSuite> Serialize for TokenRequest<CS> {
    fn tls_serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::result::Result<usize, tls_codec::Error> {
        self.token_type.tls_serialize(writer)?;
        self.truncated_token_key_id.tls_serialize(writer)?;
        writer.write_all(&self.blinded_msg)?;
        Ok(self.token_type.tls_serialized_len()
            + self.truncated_token_key_id.tls_serialized_len()
            + self.blinded_msg.len())
    }
}

impl<CS: PrivateCipherSuite> Deserialize for TokenRequest<CS> {
    fn tls_deserialize<R: std::io::Read>(
        bytes: &mut R,
    ) -> std::result::Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let token_type = TokenType::tls_deserialize(bytes)?;
        let truncated_token_key_id = TruncatedTokenKeyId::tls_deserialize(bytes)?;
        let mut blinded_msg = vec![0u8; <<CS::Group as Group>::ElemLen as Unsigned>::USIZE];
        bytes.read_exact(&mut blinded_msg)?;
        Ok(TokenRequest {
            _marker: std::marker::PhantomData,
            token_type,
            truncated_token_key_id,
            blinded_msg,
        })
    }
}
