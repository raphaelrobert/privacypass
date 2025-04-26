use privacypass::public_tokens::TokenRequest;
use privacypass::test_utils::public_memory_stores::*;

use privacypass::{
    auth::authenticate::TokenChallenge,
    public_tokens::{public_key_to_truncated_token_key_id, server::*},
    test_utils::public_memory_stores::IssuerMemoryKeyStore,
    TokenType,
};
use rand::thread_rng;

#[tokio::test]
async fn public_tokens_cycle() {
    let rng = &mut thread_rng();

    // Server: Instantiate in-memory keystore and nonce store.
    let issuer_key_store = IssuerMemoryKeyStore::default();
    let origin_key_store = OriginMemoryKeyStore::default();
    let nonce_store = MemoryNonceStore::default();

    // Server: Create servers for issuer and origin
    let issuer_server = IssuerServer::new();
    let origin_server = OriginServer::new();

    // Issuer server: Create a new keypair
    let public_key = issuer_server
        .create_keypair(rng, &issuer_key_store)
        .await
        .unwrap();

    origin_key_store
        .insert(
            public_key_to_truncated_token_key_id(&public_key),
            public_key.clone(),
        )
        .await;

    // Generate a challenge
    let token_challenge = TokenChallenge::new(
        TokenType::PublicToken,
        "example.com",
        None,
        &["example.com".to_string()],
    );
    let challenge_digest = token_challenge.digest().unwrap();

    // Client: Prepare a TokenRequest after having received a challenge
    let (token_request, token_state) =
        TokenRequest::new(rng, public_key, &token_challenge).unwrap();

    // Issuer server: Issue a TokenResponse
    let token_response = issuer_server
        .issue_token_response(&issuer_key_store, token_request)
        .await
        .unwrap();

    // Client: Turn the TokenResponse into a Token
    let token = token_response.issue_token(&token_state).unwrap();

    // Origin server: Compare the challenge digest
    assert_eq!(token.challenge_digest(), &challenge_digest);

    // Origin server: Redeem the token
    assert!(origin_server
        .redeem_token(&origin_key_store, &nonce_store, token.clone())
        .await
        .is_ok());

    // Origin server: Test double spend protection
    assert_eq!(
        origin_server
            .redeem_token(&origin_key_store, &nonce_store, token)
            .await,
        Err(RedeemTokenError::DoubleSpending)
    );
}
