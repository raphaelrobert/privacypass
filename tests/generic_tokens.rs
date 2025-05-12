use p384::NistP384;
use privacypass::{
    TokenType,
    auth::authenticate::TokenChallenge,
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
use rand::thread_rng;
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

    let rng = &mut thread_rng();

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

    // Client: Batch the token requests
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
