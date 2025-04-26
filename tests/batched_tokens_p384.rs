mod batched_memory_stores;

use batched_memory_stores::*;

use privacypass::{
    auth::authenticate::TokenChallenge,
    batched_tokens_p384::{server::*, TokenRequest},
    TokenType,
};

#[tokio::test]
async fn batched_tokens_p384_cycle() {
    // Number of tokens to issue
    let nr = 100;

    // Server: Instantiate in-memory keystore and nonce store.
    let key_store = MemoryKeyStoreP384::default();
    let nonce_store = MemoryNonceStore::default();

    // Server: Create server
    let server = Server::new();

    // Server: Create a new keypair
    let public_key = server.create_keypair(&key_store).await.unwrap();

    // Generate a challenge
    let challenge = TokenChallenge::new(
        TokenType::BatchedTokenP384,
        "example.com",
        None,
        &["example.com".to_string()],
    );

    // Client: Prepare a TokenRequest after having received a challenge
    let (token_request, token_state) = TokenRequest::new(public_key, &challenge, nr).unwrap();

    // Server: Issue a TokenResponse
    let token_response = server
        .issue_token_response(&key_store, token_request)
        .await
        .unwrap();

    // Client: Turn the TokenResponse into a Token
    let tokens = token_response.issue_tokens(&token_state).unwrap();

    // Server: Compare the challenge digest
    for token in &tokens {
        assert_eq!(token.challenge_digest(), &challenge.digest().unwrap());
    }

    // Server: Redeem the token
    for token in &tokens {
        assert!(server
            .redeem_token(&key_store, &nonce_store, token.clone())
            .await
            .is_ok());
    }

    // Server: Test double spend protection
    for token in &tokens {
        assert_eq!(
            server
                .redeem_token(&key_store, &nonce_store, token.clone())
                .await,
            Err(RedeemTokenError::DoubleSpending)
        );
    }
}
