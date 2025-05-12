use p384::NistP384;
use privacypass::{
    PPCipherSuite,
    amortized_tokens::{TokenRequest, server::*},
    auth::authenticate::TokenChallenge,
    common::errors::RedeemTokenError,
    test_utils::{nonce_store::MemoryNonceStore, private_memory_store::MemoryKeyStoreVoprf},
};
use voprf::Ristretto255;

#[tokio::test]
async fn amortized_tokens() {
    amortized_tokens_cycle_type::<NistP384>().await;
    amortized_tokens_cycle_type::<Ristretto255>().await;
}

async fn amortized_tokens_cycle_type<CS: PPCipherSuite>() {
    // Number of tokens to issue
    let nr = 10;

    // Server: Instantiate in-memory keystore and nonce store.
    let key_store = MemoryKeyStoreVoprf::<CS>::default();
    let nonce_store = MemoryNonceStore::default();

    // Server: Create server
    let server = Server::new();

    // Server: Create a new keypair
    let public_key = server.create_keypair(&key_store).await.unwrap();

    // Generate a challenge
    let challenge = TokenChallenge::new(
        CS::token_type(),
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
        assert!(
            server
                .redeem_token(&key_store, &nonce_store, token.clone())
                .await
                .is_ok()
        );
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
