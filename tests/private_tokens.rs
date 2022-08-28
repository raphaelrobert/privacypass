mod private_memory_stores;

use private_memory_stores::*;

use privacypass::{
    auth::authenticate::TokenChallenge,
    private_tokens::{client::*, server::*},
    TokenType,
};

#[tokio::test]
async fn private_tokens_cycle() {
    // Server: Instantiate in-memory keystore and nonce store.
    let key_store = MemoryKeyStore::default();
    let nonce_store = MemoryNonceStore::default();

    // Server: Create server
    let mut server = Server::new();

    // Server: Create a new keypair
    let public_key = server.create_keypair(&key_store).await.unwrap();

    // Client: Create client
    let mut client = Client::new(public_key);

    // Generate a challenge
    let challenge = TokenChallenge::new(
        TokenType::Private,
        "example.com",
        None,
        &["example.com".to_string()],
    );

    // Client: Prepare a TokenRequest after having received a challenge
    let (token_request, token_state) = client.issue_token_request(&challenge).unwrap();

    // Server: Issue a TokenResponse
    let token_response = server
        .issue_token_response(&key_store, token_request)
        .await
        .unwrap();

    // Client: Turn the TokenResponse into a Token
    let token = client.issue_token(&token_response, &token_state).unwrap();

    // Server: Compare the challenge digest
    assert_eq!(token.challenge_digest(), &challenge.digest().unwrap());

    // Server: Redeem the token
    assert!(server
        .redeem_token(&key_store, &nonce_store, token.clone())
        .await
        .is_ok());

    // Server: Test double spend protection
    assert_eq!(
        server.redeem_token(&key_store, &nonce_store, token).await,
        Err(RedeemTokenError::DoubleSpending)
    );
}
