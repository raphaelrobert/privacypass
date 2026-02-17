//! Server-side implementation of Privately Verifiable Token protocol.

use p384::NistP384;
use voprf::Ristretto255;

use crate::{
    DEFAULT_MAX_BATCH_SIZE,
    common::{errors::IssueTokenResponseError, store::PrivateKeyStore},
    private_tokens::server::Server as PrivateServer,
    public_tokens::server::{IssuerKeyStore, IssuerServer},
};

use super::GenericBatchTokenRequest;
use super::GenericBatchTokenResponse;

/// Server side implementation of Generic Tokens.
#[derive(Debug)]
pub struct Server {
    max_batch_size: usize,
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

impl Server {
    /// Creates a new server.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_batch_size: DEFAULT_MAX_BATCH_SIZE,
        }
    }

    /// Creates a new server with a custom maximum batch size. The default is
    /// [`DEFAULT_MAX_BATCH_SIZE`](crate::DEFAULT_MAX_BATCH_SIZE).
    #[must_use]
    pub const fn with_max_batch_size(max_batch_size: usize) -> Self {
        Self { max_batch_size }
    }

    /// Issues token responses.
    ///
    /// # Errors
    /// Returns an error if the token request is invalid.
    pub async fn issue_token_responses<
        P384KS: PrivateKeyStore<CS = NistP384>,
        R255KS: PrivateKeyStore<CS = Ristretto255>,
        IKS: IssuerKeyStore,
    >(
        &self,
        private_p384_key_store: &P384KS,
        private_ristretto255_key_store: &R255KS,
        issuer_key_store: &IKS,
        token_request: GenericBatchTokenRequest,
    ) -> Result<GenericBatchTokenResponse, IssueTokenResponseError> {
        let batch_size = token_request.token_requests.len();
        if batch_size > self.max_batch_size {
            return Err(IssueTokenResponseError::BatchTooLarge {
                max: self.max_batch_size,
                size: batch_size,
            });
        }
        let mut token_responses = Vec::new();
        for request in token_request.token_requests {
            match request {
                super::GenericTokenRequest::PrivateP384(token_request) => {
                    let token_response = PrivateServer::new()
                        .issue_token_response(private_p384_key_store, *token_request)
                        .await?;
                    let optional_token_response = super::OptionalTokenResponse {
                        token_response: Some(super::GenericTokenResponse::PrivateP384(Box::new(
                            token_response,
                        ))),
                    };
                    token_responses.push(optional_token_response);
                }
                super::GenericTokenRequest::Public(token_request) => {
                    let token_response = IssuerServer::new()
                        .issue_token_response(issuer_key_store, *token_request)
                        .await?;
                    let optional_token_response = super::OptionalTokenResponse {
                        token_response: Some(super::GenericTokenResponse::Public(Box::new(
                            token_response,
                        ))),
                    };
                    token_responses.push(optional_token_response);
                }
                super::GenericTokenRequest::PrivateRistretto255(token_request) => {
                    let token_response = PrivateServer::new()
                        .issue_token_response(private_ristretto255_key_store, *token_request)
                        .await?;
                    let optional_token_response = super::OptionalTokenResponse {
                        token_response: Some(super::GenericTokenResponse::PrivateRistretto255(
                            Box::new(token_response),
                        )),
                    };
                    token_responses.push(optional_token_response);
                }
            }
        }
        Ok(GenericBatchTokenResponse { token_responses })
    }
}
