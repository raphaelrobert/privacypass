//! Request implementation of the Amortized Tokens protocol.

use rand::{Rng, rngs::OsRng};
use tls_codec::{Deserialize, Serialize, Size};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
use typenum::Unsigned;
use voprf::{Group, Result, VoprfClient};

use crate::{
    ChallengeDigest, Nonce, PPCipherSuite, TokenInput, TokenType, TruncatedTokenKeyId,
    auth::authenticate::TokenChallenge,
    common::{
        errors::IssueTokenRequestError,
        private::{PublicKey, public_key_to_token_key_id},
    },
    truncate_token_key_id,
};

/// State that is kept between the token requests and token responses.
pub struct TokenState<CS: PPCipherSuite> {
    pub(crate) clients: Vec<VoprfClient<CS>>,
    pub(crate) token_inputs: Vec<TokenInput>,
    pub(crate) challenge_digest: ChallengeDigest,
    pub(crate) public_key: PublicKey<CS>,
}

impl<CS: PPCipherSuite> std::fmt::Debug for TokenState<CS> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenState")
            .field("clients", &self.clients.len())
            .field("token_inputs", &self.token_inputs.len())
            .field("challenge_digest", &self.challenge_digest)
            .field("public_key", &"public key".to_string())
            .finish()
    }
}

/// Blinded element as specified in the spec:
///
/// ```c
/// struct {
///     uint8_t blinded_element[Ne];
/// } BlindedElement;
/// ```
#[derive(Debug)]
pub struct BlindedElement<CS: PPCipherSuite> {
    pub(crate) _marker: std::marker::PhantomData<CS>,
    pub(crate) blinded_element: Vec<u8>,
}

/// Token request as specified in the spec:
///
/// ```c
/// struct {
///     uint16_t token_type;
///     uint8_t truncated_token_key_id;
///     BlindedElement blinded_element<V>;
/// } AmortizedBatchTokenRequest;
/// ```
#[derive(Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct AmortizedBatchTokenRequest<CS: PPCipherSuite> {
    pub(crate) token_type: TokenType,
    pub(crate) truncated_token_key_id: TruncatedTokenKeyId,
    pub(crate) blinded_elements: Vec<BlindedElement<CS>>,
}

impl<CS: PPCipherSuite> AmortizedBatchTokenRequest<CS> {
    /// Returns the number of blinded elements
    #[must_use]
    pub fn nr(&self) -> usize {
        self.blinded_elements.len()
    }
}

impl<CS: PPCipherSuite> AmortizedBatchTokenRequest<CS> {
    /// Issue a new token request.
    ///
    /// # Errors
    /// Returns an error if the challenge is invalid.
    pub fn new(
        public_key: PublicKey<CS>,
        challenge: &TokenChallenge,
        nr: u16,
    ) -> Result<(AmortizedBatchTokenRequest<CS>, TokenState<CS>), IssueTokenRequestError> {
        let mut nonces = Vec::with_capacity(nr as usize);

        for _ in 0..nr {
            let nonce: Nonce = OsRng.r#gen();
            nonces.push(nonce);
        }

        Self::issue_token_request_internal(public_key, challenge, nonces, None)
    }

    /// Issue a token request.
    fn issue_token_request_internal(
        public_key: PublicKey<CS>,
        challenge: &TokenChallenge,
        nonces: Vec<Nonce>,
        _blinds: Option<Vec<<CS::Group as Group>::Scalar>>,
    ) -> Result<(AmortizedBatchTokenRequest<CS>, TokenState<CS>), IssueTokenRequestError> {
        let challenge_digest = challenge
            .digest()
            .map_err(|_| IssueTokenRequestError::InvalidTokenChallenge)?;

        let token_key_id = public_key_to_token_key_id::<CS>(&public_key);

        let mut clients = Vec::with_capacity(nonces.len());
        let mut token_inputs = Vec::with_capacity(nonces.len());
        let mut blinded_elements = Vec::with_capacity(nonces.len());

        #[cfg(feature = "kat")]
        let mut blinds_iter = _blinds.iter().flatten();

        for nonce in nonces {
            // nonce = random(32)
            // challenge_digest = SHA256(challenge)
            // token_input = concat(0xXXXX, nonce, challenge_digest, token_key_id)
            // blind, blinded_element = client_context.Blind(token_input)

            let token_input = TokenInput::new(
                challenge.token_type(),
                nonce,
                challenge_digest,
                token_key_id,
            );

            let blind = VoprfClient::<CS>::blind(&token_input.serialize(), &mut OsRng)
                .map_err(|_| IssueTokenRequestError::BlindingError)?;

            #[cfg(feature = "kat")]
            let blind = if _blinds.is_some() {
                VoprfClient::<CS>::deterministic_blind_unchecked(
                    &token_input.serialize(),
                    *blinds_iter.next().unwrap(),
                )
                .map_err(|_| IssueTokenRequestError::BlindingError)?
            } else {
                blind
            };

            let serialized_blinded_element = blind.message.serialize().to_vec();
            let blinded_element = BlindedElement {
                _marker: std::marker::PhantomData,
                blinded_element: serialized_blinded_element,
            };

            clients.push(blind.state);
            token_inputs.push(token_input);
            blinded_elements.push(blinded_element);
        }

        let token_request = AmortizedBatchTokenRequest {
            token_type: challenge.token_type(),
            truncated_token_key_id: truncate_token_key_id(&token_key_id),
            blinded_elements,
        };

        let token_state = TokenState {
            clients,
            token_inputs,
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
        nonces: Vec<Nonce>,
        blind: Vec<<CS::Group as Group>::Scalar>,
    ) -> Result<(AmortizedBatchTokenRequest<CS>, TokenState<CS>), IssueTokenRequestError> {
        Self::issue_token_request_internal(public_key, challenge, nonces, Some(blind))
    }
}

impl<CS: PPCipherSuite> Size for BlindedElement<CS> {
    fn tls_serialized_len(&self) -> usize {
        <<CS::Group as Group>::ElemLen as Unsigned>::USIZE
    }
}

impl<CS: PPCipherSuite> Serialize for BlindedElement<CS> {
    fn tls_serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::result::Result<usize, tls_codec::Error> {
        writer.write_all(&self.blinded_element)?;
        Ok(self.blinded_element.len())
    }
}

impl<CS: PPCipherSuite> Deserialize for BlindedElement<CS> {
    fn tls_deserialize<R: std::io::Read>(
        bytes: &mut R,
    ) -> std::result::Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let mut blinded_element = vec![0u8; <<CS::Group as Group>::ElemLen as Unsigned>::USIZE];
        bytes.read_exact(&mut blinded_element)?;
        Ok(BlindedElement {
            _marker: std::marker::PhantomData,
            blinded_element,
        })
    }
}
