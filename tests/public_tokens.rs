mod public_memory_stores;

use public_memory_stores::*;

use privacypass::{
    auth::authenticate::TokenChallenge,
    public_tokens::{client::*, public_key_to_token_key_id, server::*},
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
    let key_pair = issuer_server
        .create_keypair(&mut rand::thread_rng(), &issuer_key_store)
        .await
        .unwrap();

    let public_key = key_pair.pk;

    origin_key_store
        .insert(public_key_to_token_key_id(&public_key), public_key.clone())
        .await;

    // Client: Create client
    let mut client = Client::new(public_key);

    // Generate a challenge
    let token_challenge = TokenChallenge::new(
        TokenType::Public,
        "example.com",
        None,
        &["example.com".to_string()],
    );
    let challenge_digest = token_challenge.digest().unwrap();

    // Client: Prepare a TokenRequest after having received a challenge
    let (token_request, token_state) = client.issue_token_request(rng, token_challenge).unwrap();

    // Issuer server: Issue a TokenResponse
    let token_response = issuer_server
        .issue_token_response(&issuer_key_store, token_request)
        .await
        .unwrap();

    // Client: Turn the TokenResponse into a Token
    let token = client.issue_token(token_response, &token_state).unwrap();

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
