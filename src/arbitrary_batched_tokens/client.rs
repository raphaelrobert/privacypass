//! Client-side implementation of the Privately Verifiable Token protocol.

use thiserror::Error;

use super::{
    ArbitraryBatchToken, ArbitraryBatchTokenRequest, ArbitraryBatchTokenResponse,
    BatchTokenRequest, BatchTokenResponse,
};

/// Client-side state that is kept between the token requests and token responses.
#[derive(Debug)]
pub enum ArbitraryBatchTokenState {
    /// Private token state
    PrivateTokenState(Box<crate::private_tokens::client::TokenState>),
    /// Public token state
    PublicTokenState(Box<crate::public_tokens::client::TokenState>),
}

impl From<crate::private_tokens::client::TokenState> for ArbitraryBatchTokenState {
    fn from(state: crate::private_tokens::client::TokenState) -> Self {
        ArbitraryBatchTokenState::PrivateTokenState(Box::new(state))
    }
}

impl From<crate::public_tokens::client::TokenState> for ArbitraryBatchTokenState {
    fn from(state: crate::public_tokens::client::TokenState) -> Self {
        ArbitraryBatchTokenState::PublicTokenState(Box::new(state))
    }
}

/// Token states that are kept between the token requests and token responses.
#[derive(Debug)]
pub struct TokenStates {
    token_states: Vec<ArbitraryBatchTokenState>,
}

/// Errors that can occur when issuing token requests.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum IssueTokenRequestError {
    #[error("Unsupported token type")]
    /// Error when the token type is not supported.
    UnsupportedTokenType,
    /// Private issue token request error.
    #[error(transparent)]
    PrivateIssueTokenRequestError(#[from] crate::private_tokens::client::IssueTokenRequestError),
    /// Public issue token request error.
    #[error(transparent)]
    PublicIssueTokenRequestError(#[from] crate::public_tokens::client::IssueTokenRequestError),
}

/// Errors that can occur when issuing tokens.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum IssueTokenError {
    #[error("Invalid TokenResponse")]
    /// Error when the token response is invalid.
    InvalidTokenResponse,
    /// Private issue token error.
    #[error(transparent)]
    PrivateIssueTokenError(#[from] crate::private_tokens::client::IssueTokenError),
    /// Public issue token error.
    #[error(transparent)]
    PublicIssueTokenError(#[from] crate::public_tokens::client::IssueTokenError),
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
                        ArbitraryBatchTokenResponse::PrivateTokenResponse(response),
                        ArbitraryBatchTokenState::PrivateTokenState(state),
                    ) => {
                        let token = response.issue_token(state).map(|t| t.into())?;
                        tokens.push(token);
                    }
                    (
                        ArbitraryBatchTokenResponse::PublicTokenResponse(response),
                        ArbitraryBatchTokenState::PublicTokenState(state),
                    ) => {
                        let token = response.issue_token(state).map(|t| t.into())?;
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
