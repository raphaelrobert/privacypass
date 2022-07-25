mod batched_memory_stores;

use batched_memory_stores::*;

use sha2::{Digest, Sha256};
use voprf::*;

use privacypass::{
    auth::TokenChallenge,
    batched_tokens::{client::*, server::*},
    TokenType,
};

#[tokio::test]
async fn batched_tokens_cycle() {
    // Number of tokens to issue
    let nr = 100;

    // Server: Instantiate in-memory keystore and nonce store.
    let mut key_store = MemoryKeyStore::default();
    let mut nonce_store = MemoryNonceStore::default();

    // Server: Create server
    let mut server = Server::<Ristretto255>::new();

    // Server: Create a new keypair
    let public_key = server.create_keypair(&mut key_store, 1).await.unwrap();

    // Client: Create client
    let mut client = Client::<Ristretto255>::new(1, public_key);

    // Generate a challenge
    let challenge = TokenChallenge::new(
        TokenType::Batched,
        "example.com",
        None,
        vec!["example.com".to_string()],
    );

    let challenge_digest = Sha256::digest(challenge.serialize()).to_vec();

    // Client: Prepare a TokenRequest after having received a challenge
    let (token_request, token_states) = client.issue_token_request(&challenge, nr).unwrap();

    // Server: Issue a TokenResponse
    let token_response = server
        .issue_token_response(&key_store, token_request)
        .await
        .unwrap();

    // Client: Turn the TokenResponse into a Token
    let tokens = client.issue_token(token_response, token_states).unwrap();

    // Server: Compare the challenge digest
    for token in &tokens {
        assert_eq!(token.challenge_digest(), &challenge_digest);
    }

    // Server: Redeem the token
    for token in &tokens {
        assert!(server
            .redeem_token(&mut key_store, &mut nonce_store, token.clone())
            .await
            .is_ok());
    }

    // Server: Test double spend protection
    for token in &tokens {
        assert_eq!(
            server
                .redeem_token(&mut key_store, &mut nonce_store, token.clone())
                .await,
            Err(RedeemTokenError::DoubleSpending)
        );
    }
}
