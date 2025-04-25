//! Server-side implementation of Privately Verifiable Token protocol.

use thiserror::Error;

use crate::{
    private_tokens::server::{PrivateKeyStore, Server as PrivateServer},
    public_tokens::server::{IssuerKeyStore, IssuerServer},
};

use super::BatchTokenRequest;
use super::BatchTokenResponse;

/// Errors that can occur when creating a keypair.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum CreateKeypairError {
    #[error("Seed is too long")]
    /// Error when the seed is too long.
    SeedError,
}

/// Errors that can occur when issuing the token response.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum IssueTokenResponseError {
    /// Private issue token response error.
    #[error(transparent)]
    PrivateIssueTokenResponseError(#[from] crate::private_tokens::server::IssueTokenResponseError),
    /// Public issue token response error.
    #[error(transparent)]
    PublicIssueTokenResponseError(#[from] crate::public_tokens::server::IssueTokenResponseError),
}

/// Errors that can occur when redeeming the token.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum RedeemTokenError {
    #[error("Key ID not found")]
    /// Error when the key ID is not found.
    KeyIdNotFound,
    #[error("The token has already been redeemed")]
    /// Error when the token has already been redeemed.
    DoubleSpending,
    #[error("The token is invalid")]
    /// Error when the token is invalid.
    InvalidToken,
}

/// Server side implementation of Arbitrary Batched Tokens.
#[derive(Default, Debug)]
pub struct Server {}

impl Server {
    /// Creates a new server.
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }

    /// Issues token responses.
    ///
    /// # Errors
    /// Returns an error if the token request is invalid.
    pub async fn issue_token_responses<PKS: PrivateKeyStore, IKS: IssuerKeyStore>(
        &self,
        private_key_store: &PKS,
        issuer_key_store: &IKS,
        token_request: BatchTokenRequest,
    ) -> Result<BatchTokenResponse, IssueTokenResponseError> {
        let mut token_responses = Vec::new();
        for request in token_request.token_requests {
            match request {
                super::ArbitraryBatchTokenRequest::PrivateTokenRequest(token_request) => {
                    let token_response = PrivateServer::new()
                        .issue_token_response(private_key_store, *token_request)
                        .await?;
                    let optional_token_response = super::OptionalTokenResponse {
                        token_response: Some(
                            super::ArbitraryBatchTokenResponse::PrivateTokenResponse(Box::new(
                                token_response,
                            )),
                        ),
                    };
                    token_responses.push(optional_token_response);
                }
                super::ArbitraryBatchTokenRequest::PublicTokenRequest(token_request) => {
                    let token_response = IssuerServer::new()
                        .issue_token_response(issuer_key_store, *token_request)
                        .await?;
                    let optional_token_response = super::OptionalTokenResponse {
                        token_response: Some(
                            super::ArbitraryBatchTokenResponse::PublicTokenResponse(Box::new(
                                token_response,
                            )),
                        ),
                    };
                    token_responses.push(optional_token_response);
                }
            }
        }
        Ok(BatchTokenResponse { token_responses })
    }
}
