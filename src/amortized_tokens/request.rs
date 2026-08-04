//! Request implementation of the Amortized Tokens protocol.

use rand::{TryRng, rngs::SysRng};
use tls_codec::{Deserialize, Serialize, Size, TlsDeserialize, TlsSerialize, TlsSize};
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

/// State that is kept between the token requests and token responses.
pub struct TokenState<CS: PrivateCipherSuite> {
    pub(crate) clients: Vec<VoprfClient<CS>>,
    pub(crate) token_inputs: Vec<TokenInput>,
    pub(crate) challenge_digest: ChallengeDigest,
    pub(crate) public_key: PublicKey<CS>,
}

impl<CS: PrivateCipherSuite> std::fmt::Debug for TokenState<CS> {
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
pub struct BlindedElement<CS: PrivateCipherSuite> {
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
pub struct AmortizedBatchTokenRequest<CS: PrivateCipherSuite> {
    pub(crate) token_type: TokenType,
    pub(crate) truncated_token_key_id: TruncatedTokenKeyId,
    pub(crate) blinded_elements: Vec<BlindedElement<CS>>,
}

impl<CS: PrivateCipherSuite> AmortizedBatchTokenRequest<CS> {
    /// Returns the number of blinded elements
    #[must_use]
    pub fn nr(&self) -> usize {
        self.blinded_elements.len()
    }

    /// Returns the truncated token key ID
    #[must_use]
    pub fn truncated_token_key_id(&self) -> TruncatedTokenKeyId {
        self.truncated_token_key_id
    }
}

impl<CS: PrivateCipherSuite> AmortizedBatchTokenRequest<CS> {
    /// Issue a new token request.
    ///
    /// # Errors
    /// Returns an error if the challenge is invalid.
    pub fn new(
        public_key: PublicKey<CS>,
        challenge: &TokenChallenge,
        nr: u16,
    ) -> Result<(AmortizedBatchTokenRequest<CS>, TokenState<CS>), IssueTokenRequestError> {
        let challenge_digest = challenge
            .digest()
            .map_err(|source| IssueTokenRequestError::InvalidTokenChallenge { source })?;

        let token_key_id = public_key_to_token_key_id::<CS>(&public_key);

        let mut clients = Vec::with_capacity(nr as usize);
        let mut token_inputs = Vec::with_capacity(nr as usize);
        let mut blinded_elements = Vec::with_capacity(nr as usize);

        for _ in 0..nr {
            // nonce = random(32)
            // challenge_digest = SHA256(challenge)
            // token_input = concat(0xXXXX, nonce, challenge_digest, token_key_id)
            // blind, blinded_element = client_context.Blind(token_input)

            let mut nonce = Nonce::default();
            SysRng
                .try_fill_bytes(&mut nonce)
                .map_err(|source| IssueTokenRequestError::RngFailed { source })?;

            let token_input = TokenInput::new(
                challenge.token_type(),
                nonce,
                challenge_digest,
                token_key_id,
            );

            let blind_result = VoprfClient::<CS>::blind(&token_input.serialize(), &mut SysRng)
                .map_err(|source| IssueTokenRequestError::BlindingError {
                    source: source.into(),
                })?;

            let serialized_blinded_element = blind_result.message.serialize().to_vec();
            let blinded_element = BlindedElement {
                _marker: std::marker::PhantomData,
                blinded_element: serialized_blinded_element,
            };

            clients.push(blind_result.state);
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

    /// Issue a token request from caller-supplied blinding scalars.
    ///
    /// # Errors
    /// Returns [`DeterministicIssuanceError::BlindCountMismatch`] if the number
    /// of blinds differs from the number of nonces and
    /// [`DeterministicIssuanceError::ZeroBlind`] if a blinding scalar is zero.
    /// Challenge and blinding failures are wrapped transparently as
    /// [`IssueTokenRequestError`].
    #[cfg(feature = "deterministic-issuance")]
    pub fn issue_token_request_with_params(
        public_key: PublicKey<CS>,
        challenge: &TokenChallenge,
        nonces: Vec<Nonce>,
        blinds: Vec<Scalar<CS>>,
    ) -> Result<(AmortizedBatchTokenRequest<CS>, TokenState<CS>), DeterministicIssuanceError> {
        if nonces.len() != blinds.len() {
            return Err(DeterministicIssuanceError::BlindCountMismatch {
                nonces: nonces.len(),
                blinds: blinds.len(),
            });
        }

        for (index, blind) in blinds.iter().enumerate() {
            if bool::from(CS::Group::is_zero_scalar(*blind)) {
                return Err(DeterministicIssuanceError::ZeroBlind { index });
            }
        }

        let challenge_digest = challenge
            .digest()
            .map_err(|source| IssueTokenRequestError::InvalidTokenChallenge { source })?;

        let token_key_id = public_key_to_token_key_id::<CS>(&public_key);

        let mut clients = Vec::with_capacity(nonces.len());
        let mut token_inputs = Vec::with_capacity(nonces.len());
        let mut blinded_elements = Vec::with_capacity(nonces.len());

        for (nonce, blind) in nonces.into_iter().zip(blinds) {
            let token_input = TokenInput::new(
                challenge.token_type(),
                nonce,
                challenge_digest,
                token_key_id,
            );

            let blind_result =
                VoprfClient::<CS>::deterministic_blind_unchecked(&token_input.serialize(), blind)
                    .map_err(|source| IssueTokenRequestError::BlindingError {
                    source: source.into(),
                })?;

            let serialized_blinded_element = blind_result.message.serialize().to_vec();
            let blinded_element = BlindedElement {
                _marker: std::marker::PhantomData,
                blinded_element: serialized_blinded_element,
            };

            clients.push(blind_result.state);
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
}

impl<CS: PrivateCipherSuite> Size for BlindedElement<CS> {
    fn tls_serialized_len(&self) -> usize {
        <<CS::Group as Group>::ElemLen as Unsigned>::USIZE
    }
}

impl<CS: PrivateCipherSuite> Serialize for BlindedElement<CS> {
    fn tls_serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::result::Result<usize, tls_codec::Error> {
        writer.write_all(&self.blinded_element)?;
        Ok(self.blinded_element.len())
    }
}

impl<CS: PrivateCipherSuite> Deserialize for BlindedElement<CS> {
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
