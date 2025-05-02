//! Client-side implementation of the Privately Verifiable Token protocol.

use p384::NistP384;
use voprf::Ristretto255;

use crate::common::errors::IssueTokenError;

use super::{
    ArbitraryBatchToken, ArbitraryBatchTokenRequest, ArbitraryBatchTokenResponse,
    BatchTokenRequest, BatchTokenResponse,
};

/// Client-side state that is kept between the token requests and token responses.
#[derive(Debug)]
pub enum ArbitraryBatchTokenState {
    /// Private p384 token state
    PrivateP384(Box<crate::private_tokens::client::TokenState<NistP384>>),
    /// Public token state
    Public(Box<crate::public_tokens::client::TokenState>),
    /// Private ristretto255 token state
    PrivateRistretto255(Box<crate::private_tokens::client::TokenState<Ristretto255>>),
}

impl From<crate::private_tokens::client::TokenState<NistP384>> for ArbitraryBatchTokenState {
    fn from(state: crate::private_tokens::client::TokenState<NistP384>) -> Self {
        ArbitraryBatchTokenState::PrivateP384(Box::new(state))
    }
}

impl From<crate::private_tokens::client::TokenState<Ristretto255>> for ArbitraryBatchTokenState {
    fn from(state: crate::private_tokens::client::TokenState<Ristretto255>) -> Self {
        ArbitraryBatchTokenState::PrivateRistretto255(Box::new(state))
    }
}

impl From<crate::public_tokens::client::TokenState> for ArbitraryBatchTokenState {
    fn from(state: crate::public_tokens::client::TokenState) -> Self {
        ArbitraryBatchTokenState::Public(Box::new(state))
    }
}

/// Token states that are kept between the token requests and token responses.
#[derive(Debug)]
pub struct TokenStates {
    token_states: Vec<ArbitraryBatchTokenState>,
}

/// Builder for batch token requests.
#[derive(Debug, Default)]
pub struct BatchTokenRequestBuilder {
    token_requests: Vec<ArbitraryBatchTokenRequest>,
    token_states: Vec<ArbitraryBatchTokenState>,
}

impl BatchTokenRequestBuilder {
    /// Add a token request to the batch.
    #[must_use]
    pub fn add_token_request(
        mut self,
        token_request: ArbitraryBatchTokenRequest,
        token_state: ArbitraryBatchTokenState,
    ) -> Self {
        self.token_requests.push(token_request);
        self.token_states.push(token_state);
        self
    }

    /// Build the batch token request.
    #[must_use]
    pub fn build(self) -> (BatchTokenRequest, TokenStates) {
        (
            BatchTokenRequest {
                token_requests: self.token_requests,
            },
            TokenStates {
                token_states: self.token_states,
            },
        )
    }
}

impl BatchTokenResponse {
    /// Issues tokens.
    ///
    /// # Errors
    /// Returns an error if the response is invalid.
    pub fn issue_tokens(
        self,
        token_states: &TokenStates,
    ) -> Result<Vec<ArbitraryBatchToken>, IssueTokenError> {
        let mut tokens = Vec::new();

        for (token_response, token_state) in self
            .token_responses
            .into_iter()
            .map(|r| r.token_response)
            .zip(token_states.token_states.iter())
        {
            if let Some(response) = token_response {
                match (response, token_state) {
                    (
                        ArbitraryBatchTokenResponse::PrivateP384(response),
                        ArbitraryBatchTokenState::PrivateP384(state),
                    ) => {
                        let token = response
                            .issue_token(state)
                            .map(ArbitraryBatchToken::from_private_p384)?;
                        tokens.push(token);
                    }
                    (
                        ArbitraryBatchTokenResponse::Public(response),
                        ArbitraryBatchTokenState::Public(state),
                    ) => {
                        let token = response
                            .issue_token(state)
                            .map(ArbitraryBatchToken::from_public)?;
                        tokens.push(token);
                    }
                    (
                        ArbitraryBatchTokenResponse::PrivateRistretto255(response),
                        ArbitraryBatchTokenState::PrivateRistretto255(state),
                    ) => {
                        let token = response
                            .issue_token(state)
                            .map(ArbitraryBatchToken::from_private_ristretto)?;
                        tokens.push(token);
                    }
                    _ => {
                        return Err(IssueTokenError::InvalidTokenResponse);
                    }
                }
            }
        }

        Ok(tokens)
    }
}
