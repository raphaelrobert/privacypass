use p384::NistP384;
use privacypass::{
    PPCipherSuite,
    auth::authenticate::TokenChallenge,
    common::errors::RedeemTokenError,
    private_tokens::{TokenRequest, server::*},
    test_utils::{nonce_store::MemoryNonceStore, private_memory_store::MemoryKeyStoreVoprf},
};
use voprf::Ristretto255;

#[tokio::test]
async fn private_tokens_cycle() {
    private_tokens_cycle_type::<NistP384>().await;
    private_tokens_cycle_type::<Ristretto255>().await;
}

async fn private_tokens_cycle_type<CS: PPCipherSuite>() {
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
    let (token_request, token_state) = TokenRequest::new(public_key, &challenge).unwrap();

    // Server: Issue a TokenResponse
    let token_response = server
        .issue_token_response(&key_store, token_request)
        .await
        .unwrap();

    // Client: Turn the TokenResponse into a Token
    let token = token_response.issue_token(&token_state).unwrap();

    // Server: Compare the challenge digest
    assert_eq!(token.challenge_digest(), &challenge.digest().unwrap());

    // Server: Redeem the token
    assert!(
        server
            .redeem_token(&key_store, &nonce_store, token.clone())
            .await
            .is_ok()
    );

    // Server: Test double spend protection
    assert_eq!(
        server.redeem_token(&key_store, &nonce_store, token).await,
        Err(RedeemTokenError::DoubleSpending)
    );
}
