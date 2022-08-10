mod public_memory_stores;

use public_memory_stores::*;

use privacypass::{
    auth::authenticate::TokenChallenge,
    public_tokens::{client::*, server::*},
    TokenType,
};

#[tokio::test]
async fn public_tokens_cycle() {
    // Server: Instantiate in-memory keystore and nonce store.
    let mut issuer_key_store = IssuerMemoryKeyStore::default();
    let mut origin_key_store = OriginMemoryKeyStore::default();
    let mut nonce_store = MemoryNonceStore::default();

    let key_id = 1;

    // Server: Create servers for issuer and origin
    let mut issuer_server = IssuerServer::new();
    let mut origin_server = OriginServer::new();

    // Issuer server: Create a new keypair
    let key_pair = issuer_server
        .create_keypair(&mut issuer_key_store, key_id)
        .await
        .unwrap();

    origin_key_store.insert(key_id, key_pair.pk.clone()).await;

    // Client: Create client
    let mut client = Client::new(key_id, key_pair.pk);

    // Generate a challenge
    let challenge = TokenChallenge::new(
        TokenType::Public,
        "example.com",
        None,
        vec!["example.com".to_string()],
    );

    // Client: Prepare a TokenRequest after having received a challenge
    let (token_request, token_state) = client.issue_token_request(&challenge).unwrap();

    // Issuer server: Issue a TokenResponse
    let token_response = issuer_server
        .issue_token_response(&issuer_key_store, token_request)
        .await
        .unwrap();

    // Client: Turn the TokenResponse into a Token
    let token = client.issue_token(token_response, token_state).unwrap();

    // Origin server: Compare the challenge digest
    assert_eq!(token.challenge_digest(), &challenge.digest().unwrap());

    // Origin server: Redeem the token
    assert!(origin_server
        .redeem_token(&mut origin_key_store, &mut nonce_store, token.clone())
        .await
        .is_ok());

    // Origin server: Test double spend protection
    assert_eq!(
        origin_server
            .redeem_token(&mut origin_key_store, &mut nonce_store, token)
            .await,
        Err(RedeemTokenError::DoubleSpending)
    );
}
