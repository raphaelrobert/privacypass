//! Client-side implementation of the Privately Verifiable Token protocol.

use rand::{Rng, rngs::OsRng};
use voprf::{EvaluationElement, Group, Proof, Result, VoprfClient};

use crate::{
    ChallengeDigest, PPCipherSuite, TokenInput,
    auth::{authenticate::TokenChallenge, authorize::Token},
    common::{
        errors::{IssueTokenError, IssueTokenRequestError},
        private::{PublicKey, public_key_to_token_key_id},
    },
    truncate_token_key_id,
};

use super::{Nonce, PrivateToken, TokenRequest, TokenResponse};

/// Client-side state that is kept between the token requests and token responses.
pub struct TokenState<CS: PPCipherSuite> {
    token_input: TokenInput,
    challenge_digest: ChallengeDigest,
    client: VoprfClient<CS>,
    public_key: PublicKey<CS>,
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

        let token_key_id = public_key_to_token_key_id::<CS::Group>(&public_key);

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

impl<CS: PPCipherSuite> TokenResponse<CS> {
    /// Issue a token.
    ///
    /// # Errors
    /// Returns an error if the response is invalid.
    pub fn issue_token(
        self,
        token_state: &TokenState<CS>,
    ) -> Result<PrivateToken<CS>, IssueTokenError> {
        let evaluation_element = EvaluationElement::deserialize(&self.evaluate_msg)
            .map_err(|_| IssueTokenError::InvalidTokenResponse)?;
        let proof = Proof::deserialize(&self.evaluate_proof)
            .map_err(|_| IssueTokenError::InvalidTokenResponse)?;
        let token_input = token_state.token_input.serialize();
        // authenticator = client_context.Finalize(token_input, blind, evaluated_element, blinded_element, proof)
        let authenticator = token_state
            .client
            .finalize(
                &token_input,
                &evaluation_element,
                &proof,
                token_state.public_key,
            )
            .map_err(|_| IssueTokenError::InvalidTokenResponse)?;

        Ok(Token::new(
            CS::token_type(),
            token_state.token_input.nonce,
            token_state.challenge_digest,
            token_state.token_input.token_key_id,
            authenticator,
        ))
    }
}
