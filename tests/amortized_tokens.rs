use p384::NistP384;
use privacypass::{
    Nonce,
    amortized_tokens::{AmortizedBatchTokenRequest, server::*},
    auth::authenticate::TokenChallenge,
    common::{
        errors::{DeterministicIssuanceError, IssueTokenResponseError, RedeemTokenError},
        private::{PrivateCipherSuite, Scalar},
    },
    test_utils::{nonce_store::MemoryNonceStore, private_memory_store::MemoryKeyStoreVoprf},
};
use rand::rngs::SysRng;
use tls_codec::Serialize;
use voprf::{Group, Ristretto255};

#[tokio::test]
async fn amortized_tokens() {
    amortized_tokens_cycle_type::<NistP384>().await;
    amortized_tokens_cycle_type::<Ristretto255>().await;
}

async fn amortized_tokens_cycle_type<CS: PrivateCipherSuite>() {
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
    let (token_request, token_state) =
        AmortizedBatchTokenRequest::new(public_key, &challenge, nr).unwrap();

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

#[tokio::test]
async fn amortized_tokens_batch_too_large() {
    amortized_tokens_batch_too_large_type::<NistP384>().await;
    amortized_tokens_batch_too_large_type::<Ristretto255>().await;
}

async fn amortized_tokens_batch_too_large_type<CS: PrivateCipherSuite>() {
    let max_batch: usize = 5;
    let nr: u16 = 6;

    let key_store = MemoryKeyStoreVoprf::<CS>::default();
    let server = Server::with_max_batch_size(max_batch);

    let public_key = server.create_keypair(&key_store).await.unwrap();

    let challenge = TokenChallenge::new(
        CS::token_type(),
        "example.com",
        None,
        &["example.com".to_string()],
    );

    let (token_request, _token_state) =
        AmortizedBatchTokenRequest::new(public_key, &challenge, nr).unwrap();

    let result = server.issue_token_response(&key_store, token_request).await;

    assert!(
        matches!(
            result,
            Err(IssueTokenResponseError::BatchTooLarge { max: 5, size: 6 })
        ),
        "Expected BatchTooLarge error, got {result:?}"
    );
}

#[tokio::test]
async fn amortized_tokens_deterministic_params() {
    amortized_tokens_deterministic_params_type::<NistP384>().await;
    amortized_tokens_deterministic_params_type::<Ristretto255>().await;
}

async fn amortized_tokens_deterministic_params_type<CS: PrivateCipherSuite>() {
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

    // Client: Fix the nonces and blinds that both requests are built from
    let nonces: Vec<Nonce> = (0..nr).map(|i| [i as u8; 32]).collect();
    let blinds = (0..nr)
        .map(|_| <CS::Group as Group>::random_scalar(&mut SysRng).unwrap())
        .collect::<Vec<_>>();

    // Client: Prepare two TokenRequests from the same inputs
    let (first_request, first_state) = AmortizedBatchTokenRequest::issue_token_request_with_params(
        public_key,
        &challenge,
        nonces.clone(),
        blinds.clone(),
    )
    .unwrap();

    let (second_request, second_state) =
        AmortizedBatchTokenRequest::issue_token_request_with_params(
            public_key, &challenge, nonces, blinds,
        )
        .unwrap();

    // Client: Both requests are byte-identical
    assert_eq!(first_request.nr(), nr);
    assert_eq!(
        first_request.truncated_token_key_id(),
        second_request.truncated_token_key_id()
    );
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
    let first_tokens = first_response.issue_tokens(&first_state).unwrap();
    let second_tokens = second_response.issue_tokens(&second_state).unwrap();

    // Client: The tokens are byte-identical, i.e. the randomness of the DLEQ
    // proof does not enter the tokens
    let first_token_bytes = first_tokens
        .iter()
        .map(|token| token.tls_serialize_detached().unwrap())
        .collect::<Vec<_>>();

    let second_token_bytes = second_tokens
        .iter()
        .map(|token| token.tls_serialize_detached().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(first_token_bytes, second_token_bytes);

    // Server: Redeem the tokens of one of the two identical lists
    for token in &first_tokens {
        assert_eq!(token.challenge_digest(), &challenge.digest().unwrap());
        assert!(
            server
                .redeem_token(&key_store, &nonce_store, token.clone())
                .await
                .is_ok()
        );
    }
}

#[tokio::test]
async fn amortized_tokens_scalar_from_wide_bytes() {
    // Server: Instantiate in-memory keystore and nonce store.
    let key_store = MemoryKeyStoreVoprf::<Ristretto255>::default();
    let nonce_store = MemoryNonceStore::default();

    // Server: Create server
    let server = Server::new();

    // Server: Create a new keypair
    let public_key = server.create_keypair(&key_store).await.unwrap();

    // Generate a challenge
    let challenge = TokenChallenge::new(
        Ristretto255::token_type(),
        "example.com",
        None,
        &["example.com".to_string()],
    );

    // Client: Build blinds from wide bytes using the exported Scalar alias,
    // with no dependency on the underlying curve crate.
    let nonces: Vec<Nonce> = vec![[0u8; 32], [1u8; 32]];
    let blinds = vec![
        Scalar::<Ristretto255>::from_bytes_mod_order_wide(&[7u8; 64]),
        Scalar::<Ristretto255>::from_bytes_mod_order_wide(&[11u8; 64]),
    ];

    let (token_request, token_state) = AmortizedBatchTokenRequest::issue_token_request_with_params(
        public_key, &challenge, nonces, blinds,
    )
    .unwrap();

    // Server: Issue a TokenResponse
    let token_response = server
        .issue_token_response(&key_store, token_request)
        .await
        .unwrap();

    // Client: Turn the TokenResponse into Tokens
    let tokens = token_response.issue_tokens(&token_state).unwrap();
    assert_eq!(tokens.len(), 2);

    // Server: Redeem the tokens
    for token in &tokens {
        assert_eq!(token.challenge_digest(), &challenge.digest().unwrap());
        assert!(
            server
                .redeem_token(&key_store, &nonce_store, token.clone())
                .await
                .is_ok()
        );
    }
}

#[tokio::test]
async fn amortized_tokens_blind_count_mismatch() {
    amortized_tokens_blind_count_mismatch_type::<NistP384>().await;
    amortized_tokens_blind_count_mismatch_type::<Ristretto255>().await;
}

async fn amortized_tokens_blind_count_mismatch_type<CS: PrivateCipherSuite>() {
    let key_store = MemoryKeyStoreVoprf::<CS>::default();
    let server = Server::new();
    let public_key = server.create_keypair(&key_store).await.unwrap();

    let challenge = TokenChallenge::new(
        CS::token_type(),
        "example.com",
        None,
        &["example.com".to_string()],
    );

    let nonces: Vec<Nonce> = vec![[0u8; 32], [1u8; 32]];
    let blinds = vec![<CS::Group as Group>::random_scalar(&mut SysRng).unwrap()];

    let result = AmortizedBatchTokenRequest::<CS>::issue_token_request_with_params(
        public_key, &challenge, nonces, blinds,
    );

    assert_eq!(
        result.err(),
        Some(DeterministicIssuanceError::BlindCountMismatch {
            nonces: 2,
            blinds: 1
        })
    );
}

#[tokio::test]
async fn amortized_tokens_zero_blind() {
    amortized_tokens_zero_blind_type::<NistP384>().await;
    amortized_tokens_zero_blind_type::<Ristretto255>().await;
}

async fn amortized_tokens_zero_blind_type<CS: PrivateCipherSuite>() {
    let key_store = MemoryKeyStoreVoprf::<CS>::default();
    let server = Server::new();
    let public_key = server.create_keypair(&key_store).await.unwrap();

    let challenge = TokenChallenge::new(
        CS::token_type(),
        "example.com",
        None,
        &["example.com".to_string()],
    );

    let nonces: Vec<Nonce> = vec![[0u8; 32], [1u8; 32], [2u8; 32]];
    let mut blinds = (0..nonces.len())
        .map(|_| <CS::Group as Group>::random_scalar(&mut SysRng).unwrap())
        .collect::<Vec<_>>();

    // `Group::zero_scalar` is test-only upstream, so we derive zero ourselves
    let zero_blind = blinds[1] - &blinds[1];
    blinds[1] = zero_blind;

    let result = AmortizedBatchTokenRequest::<CS>::issue_token_request_with_params(
        public_key, &challenge, nonces, blinds,
    );

    assert_eq!(
        result.err(),
        Some(DeterministicIssuanceError::ZeroBlind { index: 1 })
    );
}
