use p384::NistP384;
use privacypass::{
    Nonce,
    auth::authenticate::TokenChallenge,
    common::{
        errors::{DeterministicIssuanceError, RedeemTokenError},
        private::PrivateCipherSuite,
    },
    private_tokens::{TokenRequest, server::*},
    test_utils::{nonce_store::MemoryNonceStore, private_memory_store::MemoryKeyStoreVoprf},
};
use rand::rngs::SysRng;
use tls_codec::Serialize;
use voprf::{Group, Ristretto255};

#[tokio::test]
async fn private_tokens_cycle() {
    private_tokens_cycle_type::<NistP384>().await;
    private_tokens_cycle_type::<Ristretto255>().await;
}

async fn private_tokens_cycle_type<CS: PrivateCipherSuite>() {
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

#[tokio::test]
async fn private_tokens_deterministic_params() {
    private_tokens_deterministic_params_type::<NistP384>().await;
    private_tokens_deterministic_params_type::<Ristretto255>().await;
}

async fn private_tokens_deterministic_params_type<CS: PrivateCipherSuite>() {
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

    // Client: Fix the nonce and blind that both requests are built from
    let nonce: Nonce = [42u8; 32];
    let blind = <CS::Group as Group>::random_scalar(&mut SysRng).unwrap();

    // Client: Prepare two TokenRequests from the same inputs
    let (first_request, first_state) =
        TokenRequest::issue_token_request_with_params(public_key, &challenge, nonce, blind)
            .unwrap();

    let (second_request, second_state) =
        TokenRequest::issue_token_request_with_params(public_key, &challenge, nonce, blind)
            .unwrap();

    // Client: Both requests are byte-identical
    assert_eq!(
        first_request.tls_serialize_detached().unwrap(),
        second_request.tls_serialize_detached().unwrap()
    );

    // Server: Issue a TokenResponse for each request
    let first_response = server
        .issue_token_response(&key_store, first_request)
        .await
        .unwrap();

    let second_response = server
        .issue_token_response(&key_store, second_request)
        .await
        .unwrap();

    // Client: Turn both TokenResponses into Tokens
    let first_token = first_response.issue_token(&first_state).unwrap();
    let second_token = second_response.issue_token(&second_state).unwrap();

    // Client: The tokens are byte-identical, i.e. the randomness of the DLEQ
    // proof does not enter the token
    assert_eq!(
        first_token.tls_serialize_detached().unwrap(),
        second_token.tls_serialize_detached().unwrap()
    );

    // Server: Redeem one of the two identical tokens
    assert_eq!(first_token.challenge_digest(), &challenge.digest().unwrap());
    assert!(
        server
            .redeem_token(&key_store, &nonce_store, first_token)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn private_tokens_zero_blind() {
    private_tokens_zero_blind_type::<NistP384>().await;
    private_tokens_zero_blind_type::<Ristretto255>().await;
}

async fn private_tokens_zero_blind_type<CS: PrivateCipherSuite>() {
    let key_store = MemoryKeyStoreVoprf::<CS>::default();
    let server = Server::new();
    let public_key = server.create_keypair(&key_store).await.unwrap();

    let challenge = TokenChallenge::new(
        CS::token_type(),
        "example.com",
        None,
        &["example.com".to_string()],
    );

    let nonce: Nonce = [42u8; 32];
    let blind = <CS::Group as Group>::random_scalar(&mut SysRng).unwrap();

    // `Group::zero_scalar` is test-only upstream, so we derive zero ourselves
    let zero_blind = blind - &blind;

    let result = TokenRequest::<CS>::issue_token_request_with_params(
        public_key, &challenge, nonce, zero_blind,
    );

    assert_eq!(
        result.err(),
        Some(DeterministicIssuanceError::ZeroBlind { index: 0 })
    );
}
