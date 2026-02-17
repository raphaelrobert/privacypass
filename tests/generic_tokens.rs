use blind_rsa_signatures::reexports::rand::rng;
use p384::NistP384;
use privacypass::{
    TokenType,
    auth::authenticate::TokenChallenge,
    common::errors::IssueTokenResponseError,
    generic_tokens::{self, GenericBatchTokenRequest, GenericToken},
    private_tokens::{self, server::Server as PrivateServer},
    public_tokens::{
        self,
        server::{IssuerServer, OriginKeyStore, OriginServer},
    },
    test_utils::{
        nonce_store::MemoryNonceStore,
        private_memory_store,
        public_memory_store::{IssuerMemoryKeyStore, OriginMemoryKeyStore},
    },
};
use voprf::Ristretto255;

#[tokio::test]
async fn generic_tokens_cycle() {
    // === Set up the private token server ===

    // Server: Instantiate in-memory keystore and nonce store.
    let private_p384_key_store = private_memory_store::MemoryKeyStoreVoprf::<NistP384>::default();
    let private_ristretto255_key_store =
        private_memory_store::MemoryKeyStoreVoprf::<Ristretto255>::default();
    let private_nonce_store = MemoryNonceStore::default();

    // Server: Create server
    let private_p384_server = PrivateServer::new();
    let private_ristretto255_server = PrivateServer::new();

    // Server: Create a new p384 keypair
    let private_p384_public_key = private_p384_server
        .create_keypair(&private_p384_key_store)
        .await
        .unwrap();

    // Server: Create a new ristretto keypair
    let private_ristretto255_public_key = private_ristretto255_server
        .create_keypair(&private_ristretto255_key_store)
        .await
        .unwrap();

    // === Set up the public token server ===

    let rng = &mut rng();

    // Server: Instantiate in-memory keystore and nonce store.
    let issuer_key_store = IssuerMemoryKeyStore::default();
    let origin_key_store = OriginMemoryKeyStore::default();
    let public_nonce_store = MemoryNonceStore::default();

    // Server: Create servers for issuer and origin
    let issuer_server = IssuerServer::new();
    let origin_server = OriginServer::new();

    // Issuer server: Create a new keypair
    let public_token_public_key = issuer_server
        .create_keypair(rng, &issuer_key_store)
        .await
        .unwrap();

    origin_key_store
        .insert(
            privacypass::public_tokens::public_key_to_truncated_token_key_id(
                &public_token_public_key,
            ),
            public_token_public_key.clone(),
        )
        .await;

    // === Set up the generic token server ===

    let server = generic_tokens::server::Server::new();

    // Client: Generate private & public challenges
    let private_p384_challenge = TokenChallenge::new(
        TokenType::PrivateP384,
        "example.com",
        None,
        &["example.com".to_string()],
    );

    let private_ristretto255_challenge = TokenChallenge::new(
        TokenType::PrivateRistretto255,
        "example.com",
        None,
        &["example.com".to_string()],
    );

    let public_challenge = TokenChallenge::new(
        TokenType::Public,
        "example.com",
        None,
        &["example.com".to_string()],
    );

    // Client: Generic batch the token requests
    let mut builder = GenericBatchTokenRequest::builder();

    for _ in 0..10 {
        // Private p384 token
        let (token_request, token_state) = private_tokens::TokenRequest::<NistP384>::new(
            private_p384_public_key,
            &private_p384_challenge,
        )
        .unwrap();
        builder = builder.add_token_request(token_request.into(), token_state.into());

        // Public token
        let (token_request, token_state) = public_tokens::TokenRequest::new(
            rng,
            public_token_public_key.clone(),
            &public_challenge,
        )
        .unwrap();
        builder = builder.add_token_request(token_request.into(), token_state.into());

        // Private ristretto255 token
        let (token_request, token_state) = private_tokens::TokenRequest::<Ristretto255>::new(
            private_ristretto255_public_key,
            &private_ristretto255_challenge,
        )
        .unwrap();
        builder = builder.add_token_request(token_request.into(), token_state.into());
    }

    let (token_request, token_states) = builder.build();

    // Server: Issue a TokenResponse
    let token_response = server
        .issue_token_responses(
            &private_p384_key_store,
            &private_ristretto255_key_store,
            &issuer_key_store,
            token_request,
        )
        .await
        .unwrap();

    // Client: Turn the TokenResponse into tokens
    let tokens = token_response.issue_tokens(&token_states).unwrap();

    // Server: Compare the challenge digest
    for (i, token) in tokens.iter().enumerate() {
        if i % 3 == 0 {
            assert_eq!(private_p384_challenge.token_type(), TokenType::PrivateP384);
            assert_eq!(
                token.challenge_digest(),
                &private_p384_challenge.digest().unwrap()
            );
        } else if i % 3 == 1 {
            assert_eq!(public_challenge.token_type(), TokenType::Public);
            assert_eq!(
                token.challenge_digest(),
                &public_challenge.digest().unwrap()
            );
        } else {
            assert_eq!(
                private_ristretto255_challenge.token_type(),
                TokenType::PrivateRistretto255
            );
            assert_eq!(
                token.challenge_digest(),
                &private_ristretto255_challenge.digest().unwrap()
            );
        }
    }

    // Server: Redeem the tokens
    for token in tokens {
        match token {
            GenericToken::PrivateP384(token) => {
                assert!(
                    private_p384_server
                        .redeem_token(
                            &private_p384_key_store,
                            &private_nonce_store,
                            *token.clone()
                        )
                        .await
                        .is_ok()
                );
            }
            GenericToken::Public(token) => {
                assert!(
                    origin_server
                        .redeem_token(&origin_key_store, &public_nonce_store, *token.clone())
                        .await
                        .is_ok()
                );
            }
            GenericToken::PrivateRistretto255(token) => {
                assert!(
                    private_ristretto255_server
                        .redeem_token(
                            &private_ristretto255_key_store,
                            &private_nonce_store,
                            *token.clone()
                        )
                        .await
                        .is_ok()
                );
            }
        }
    }
}

/// When some tokens in a batch use unknown keys, the server should return
/// `None` for those entries (partial issuance) instead of aborting the
/// entire batch.
#[tokio::test]
async fn generic_tokens_partial_issuance() {
    // Set up a P384 key store with a valid key.
    let private_p384_key_store =
        private_memory_store::MemoryKeyStoreVoprf::<NistP384>::default();
    let private_p384_server = PrivateServer::new();
    let private_p384_public_key = private_p384_server
        .create_keypair(&private_p384_key_store)
        .await
        .unwrap();

    // Ristretto255 key store with a key — used only for client-side request
    // creation, NOT passed to the server.
    let client_ristretto_key_store =
        private_memory_store::MemoryKeyStoreVoprf::<Ristretto255>::default();
    let ristretto_server = PrivateServer::new();
    let ristretto_public_key = ristretto_server
        .create_keypair(&client_ristretto_key_store)
        .await
        .unwrap();

    // Server gets an EMPTY Ristretto255 key store → those tokens will fail
    // with KeyIdNotFound.
    let empty_ristretto_key_store =
        private_memory_store::MemoryKeyStoreVoprf::<Ristretto255>::default();
    let issuer_key_store = IssuerMemoryKeyStore::default();

    let p384_challenge = TokenChallenge::new(
        TokenType::PrivateP384,
        "example.com",
        None,
        &["example.com".to_string()],
    );
    let ristretto_challenge = TokenChallenge::new(
        TokenType::PrivateRistretto255,
        "example.com",
        None,
        &["example.com".to_string()],
    );

    // Build a batch: 2 valid P384 requests interleaved with 2 invalid
    // Ristretto255 requests (unknown key on server).
    let mut builder = GenericBatchTokenRequest::builder();

    let (req, state) = private_tokens::TokenRequest::<NistP384>::new(
        private_p384_public_key,
        &p384_challenge,
    )
    .unwrap();
    builder = builder.add_token_request(req.into(), state.into());

    let (req, state) = private_tokens::TokenRequest::<Ristretto255>::new(
        ristretto_public_key,
        &ristretto_challenge,
    )
    .unwrap();
    builder = builder.add_token_request(req.into(), state.into());

    let (req, state) = private_tokens::TokenRequest::<NistP384>::new(
        private_p384_public_key,
        &p384_challenge,
    )
    .unwrap();
    builder = builder.add_token_request(req.into(), state.into());

    let (req, state) = private_tokens::TokenRequest::<Ristretto255>::new(
        ristretto_public_key,
        &ristretto_challenge,
    )
    .unwrap();
    builder = builder.add_token_request(req.into(), state.into());

    let (token_request, _token_states) = builder.build();

    let server = generic_tokens::server::Server::new();
    let response = server
        .issue_token_responses(
            &private_p384_key_store,
            &empty_ristretto_key_store,
            &issuer_key_store,
            token_request,
        )
        .await
        .expect("partial issuance should not return Err");

    // 4 entries total, 2 succeeded, 2 failed.
    assert_eq!(response.token_responses.len(), 4);
    assert_eq!(response.issued_count(), 2);

    // Indices 0 and 2 (P384) should be Some; 1 and 3 (Ristretto255) None.
    assert!(response.token_responses[0].token_response.is_some());
    assert!(response.token_responses[1].token_response.is_none());
    assert!(response.token_responses[2].token_response.is_some());
    assert!(response.token_responses[3].token_response.is_none());
}

#[tokio::test]
async fn generic_tokens_batch_too_large() {
    let max_batch = 2;

    let private_p384_key_store =
        private_memory_store::MemoryKeyStoreVoprf::<NistP384>::default();
    let private_ristretto255_key_store =
        private_memory_store::MemoryKeyStoreVoprf::<Ristretto255>::default();
    let issuer_key_store = IssuerMemoryKeyStore::default();

    let private_p384_server = PrivateServer::new();
    let private_p384_public_key = private_p384_server
        .create_keypair(&private_p384_key_store)
        .await
        .unwrap();

    let challenge = TokenChallenge::new(
        TokenType::PrivateP384,
        "example.com",
        None,
        &["example.com".to_string()],
    );

    let mut builder = GenericBatchTokenRequest::builder();
    for _ in 0..(max_batch + 1) {
        let (token_request, token_state) =
            private_tokens::TokenRequest::<NistP384>::new(
                private_p384_public_key,
                &challenge,
            )
            .unwrap();
        builder = builder
            .add_token_request(token_request.into(), token_state.into());
    }
    let (token_request, _token_states) = builder.build();

    let server = generic_tokens::server::Server::with_max_batch_size(max_batch);
    let result = server
        .issue_token_responses(
            &private_p384_key_store,
            &private_ristretto255_key_store,
            &issuer_key_store,
            token_request,
        )
        .await;

    assert!(
        matches!(
            result,
            Err(IssueTokenResponseError::BatchTooLarge {
                max: 2,
                size: 3,
            })
        ),
        "Expected BatchTooLarge error, got {result:?}"
    );
}
