//! Server-side implementation of Privately Verifiable Token protocol.

use log::warn;
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
    /// When some but not all tokens in a generic batch fail, the server
    /// produces `None` entries for the failed tokens and returns the rest.
    /// Callers should inspect [`GenericBatchTokenResponse::issued_count`]
    /// to distinguish full success (HTTP 200) from partial success
    /// (HTTP 206).
    ///
    /// # Errors
    /// Returns an error only for batch-level failures (e.g. `BatchTooLarge`).
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
        let mut token_responses = Vec::with_capacity(batch_size);
        for (index, request) in token_request.token_requests.into_iter().enumerate() {
            let result = match request {
                super::GenericTokenRequest::PrivateP384(token_request) => {
                    PrivateServer::new()
                        .issue_token_response(private_p384_key_store, *token_request)
                        .await
                        .map(|r| {
                            super::GenericTokenResponse::PrivateP384(Box::new(r))
                        })
                }
                super::GenericTokenRequest::Public(token_request) => {
                    IssuerServer::new()
                        .issue_token_response(issuer_key_store, *token_request)
                        .await
                        .map(|r| {
                            super::GenericTokenResponse::Public(Box::new(r))
                        })
                }
                super::GenericTokenRequest::PrivateRistretto255(token_request) => {
                    PrivateServer::new()
                        .issue_token_response(
                            private_ristretto255_key_store,
                            *token_request,
                        )
                        .await
                        .map(|r| {
                            super::GenericTokenResponse::PrivateRistretto255(
                                Box::new(r),
                            )
                        })
                }
            };
            let token_response = match result {
                Ok(response) => Some(response),
                Err(error) => {
                    warn!(index, error:% = error; "Failed to issue token in batch");
                    None
                }
            };
            token_responses.push(super::OptionalTokenResponse { token_response });
        }
        Ok(GenericBatchTokenResponse { token_responses })
    }
}
