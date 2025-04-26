use privacypass::{
    arbitrary_batched_tokens::{self, ArbitraryBatchToken, BatchTokenRequest},
    auth::authenticate::TokenChallenge,
    private_tokens::{self, server::Server as PrivateServer},
    public_tokens::{
        self,
        server::{IssuerServer, OriginKeyStore, OriginServer},
    },
    test_utils::{
        private_memory_stores,
        public_memory_stores::{self, IssuerMemoryKeyStore, OriginMemoryKeyStore},
    },
    TokenType,
};
use rand::thread_rng;

#[tokio::test]
async fn arbitrary_batched_tokens_cycle() {
    // === Set up the private token server ===

    // Server: Instantiate in-memory keystore and nonce store.
    let private_key_store = private_memory_stores::MemoryKeyStore::default();
    let private_nonce_store = private_memory_stores::MemoryNonceStore::default();

    // Server: Create server
    let private_server = PrivateServer::new();

    // Server: Create a new keypair
    let private_token_public_key = private_server
        .create_keypair(&private_key_store)
        .await
        .unwrap();

    // === Set up the public token server ===

    let rng = &mut thread_rng();

    // Server: Instantiate in-memory keystore and nonce store.
    let issuer_key_store = IssuerMemoryKeyStore::default();
    let origin_key_store = OriginMemoryKeyStore::default();
    let public_nonce_store = public_memory_stores::MemoryNonceStore::default();

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

    // === Set up the arbitrary batched token server ===

    let server = arbitrary_batched_tokens::server::Server::new();

    // Client: Generate private & public challenges
    let private_challenge = TokenChallenge::new(
        TokenType::PrivateToken,
        "example.com",
        None,
        &["example.com".to_string()],
    );

    let public_challenge = TokenChallenge::new(
        TokenType::PublicToken,
        "example.com",
        None,
        &["example.com".to_string()],
    );

    // Client: Batch the token requests
    let mut builder = BatchTokenRequest::builder();

    for _ in 0..10 {
        // Private token
        let (token_request, token_state) =
            private_tokens::TokenRequest::new(private_token_public_key, &private_challenge)
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
    }

    let (token_request, token_states) = builder.build();

    // Server: Issue a TokenResponse
    let token_response = server
        .issue_token_responses(&private_key_store, &issuer_key_store, token_request)
        .await
        .unwrap();

    // Client: Turn the TokenResponse into tokens
    let tokens = token_response.issue_tokens(&token_states).unwrap();

    // Server: Compare the challenge digest
    for (i, token) in tokens.iter().enumerate() {
        if i % 2 == 0 {
            assert_eq!(private_challenge.token_type(), TokenType::PrivateToken);
            assert_eq!(
                token.challenge_digest(),
                &private_challenge.digest().unwrap()
            );
        } else {
            assert_eq!(public_challenge.token_type(), TokenType::PublicToken);
            assert_eq!(
                token.challenge_digest(),
                &public_challenge.digest().unwrap()
            );
        }
    }

    // Server: Redeem the tokens
    for token in tokens {
        match token {
            ArbitraryBatchToken::PrivateToken(token) => {
                assert!(private_server
                    .redeem_token(&private_key_store, &private_nonce_store, *token.clone())
                    .await
                    .is_ok());
            }
            ArbitraryBatchToken::PublicToken(token) => {
                assert!(origin_server
                    .redeem_token(&origin_key_store, &public_nonce_store, *token.clone())
                    .await
                    .is_ok());
            }
        }
    }
}
