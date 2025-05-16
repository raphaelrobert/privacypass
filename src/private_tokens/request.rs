//! Request implementation of the Privately Verifiable Token protocol.

use rand::{Rng, rngs::OsRng};
use tls_codec::{Deserialize, Serialize, Size};
use typenum::Unsigned;
use voprf::{Group, Result, VoprfClient};

use crate::{
    ChallengeDigest, Nonce, TokenInput, TokenType, TruncatedTokenKeyId,
    auth::authenticate::TokenChallenge,
    common::{
        errors::IssueTokenRequestError,
        private::{PPCipherSuite, PublicKey, public_key_to_token_key_id},
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
pub struct TokenRequest<CS: PPCipherSuite> {
    pub(crate) _marker: std::marker::PhantomData<CS>,
    pub(crate) token_type: TokenType,
    pub(crate) truncated_token_key_id: u8,
    pub(crate) blinded_msg: Vec<u8>,
}

/// State that is kept between the token requests and token responses.
pub struct TokenState<CS: PPCipherSuite> {
    pub(crate) token_input: TokenInput,
    pub(crate) challenge_digest: ChallengeDigest,
    pub(crate) client: VoprfClient<CS>,
    pub(crate) public_key: PublicKey<CS>,
}

impl<CS: PPCipherSuite> std::fmt::Debug for TokenState<CS> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenState")
            .field("client", &"client".to_string())
            .field("token_input", &self.token_input)
            .field("challenge_digest", &self.challenge_digest)
            .field("public_key", &"public key".to_string())
            .finish()
    }
}

impl<CS: PPCipherSuite> TokenRequest<CS> {
    /// Issue a new token request.
    ///
    /// # Errors
    /// Returns an error if the challenge is invalid.
    pub fn new(
        public_key: PublicKey<CS>,
        challenge: &TokenChallenge,
    ) -> Result<(TokenRequest<CS>, TokenState<CS>), IssueTokenRequestError> {
        let nonce: Nonce = OsRng.r#gen();

        Self::issue_token_request_internal(public_key, challenge, nonce, None)
    }

    /// Issue a token request.
    fn issue_token_request_internal(
        public_key: PublicKey<CS>,
        challenge: &TokenChallenge,
        nonce: Nonce,
        _blind: Option<<CS::Group as Group>::Scalar>,
    ) -> Result<(TokenRequest<CS>, TokenState<CS>), IssueTokenRequestError> {
        let challenge_digest = challenge
            .digest()
            .map_err(|_| IssueTokenRequestError::InvalidTokenChallenge)?;

        let token_key_id = public_key_to_token_key_id::<CS>(&public_key);

        // nonce = random(32)
        // challenge_digest = SHA256(challenge)
        // token_input = concat(0x0001, nonce, challenge_digest, token_key_id)
        // blind, blinded_element = client_context.Blind(token_input)

        let token_input = TokenInput::new(CS::token_type(), nonce, challenge_digest, token_key_id);

        let blinded_element = VoprfClient::<CS>::blind(&token_input.serialize(), &mut OsRng)
            .map_err(|_| IssueTokenRequestError::BlindingError)?;

        #[cfg(feature = "kat")]
        let blinded_element = if let Some(blind) = _blind {
            VoprfClient::<CS>::deterministic_blind_unchecked(&token_input.serialize(), blind)
                .map_err(|_| IssueTokenRequestError::BlindingError)?
        } else {
            blinded_element
        };

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

    #[cfg(feature = "kat")]
    /// Issue a token request.
    pub fn issue_token_request_with_params(
        public_key: PublicKey<CS>,
        challenge: &TokenChallenge,
        nonce: Nonce,
        blind: <CS::Group as Group>::Scalar,
    ) -> Result<(TokenRequest<CS>, TokenState<CS>), IssueTokenRequestError> {
        Self::issue_token_request_internal(public_key, challenge, nonce, Some(blind))
    }
}

impl<CS: PPCipherSuite> Size for TokenRequest<CS> {
    fn tls_serialized_len(&self) -> usize {
        let len = <<CS::Group as Group>::ElemLen as Unsigned>::USIZE;
        self.token_type.tls_serialized_len()
            + self.truncated_token_key_id.tls_serialized_len()
            + len
    }
}

impl<CS: PPCipherSuite> Serialize for TokenRequest<CS> {
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

impl<CS: PPCipherSuite> Deserialize for TokenRequest<CS> {
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
