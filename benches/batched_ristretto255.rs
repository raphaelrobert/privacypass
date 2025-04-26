#[allow(clippy::duplicate_mod)]
#[path = "../tests/batched_memory_stores.rs"]
mod batched_memory_stores;

use criterion::{async_executor::FuturesExecutor, Criterion};
use tokio::runtime::Runtime;

use privacypass::{
    auth::authenticate::TokenChallenge, batched_tokens_ristretto255::TokenRequest, TokenType,
};

async fn create_batched_keypair(
    key_store: batched_memory_stores::MemoryKeyStoreRistretto255,
    server: privacypass::batched_tokens_ristretto255::server::Server,
) {
    let _public_key = server.create_keypair(&key_store).await.unwrap();
}

async fn issue_batched_token_response(
    key_store: batched_memory_stores::MemoryKeyStoreRistretto255,
    server: privacypass::batched_tokens_ristretto255::server::Server,
    token_request: privacypass::batched_tokens_ristretto255::TokenRequest,
) -> privacypass::batched_tokens_ristretto255::TokenResponse {
    server
        .issue_token_response(&key_store, token_request)
        .await
        .unwrap()
}

async fn redeem_batched_token(
    key_store: batched_memory_stores::MemoryKeyStoreRistretto255,
    nonce_store: batched_memory_stores::MemoryNonceStore,
    token: privacypass::batched_tokens_ristretto255::BatchedToken,
    server: privacypass::batched_tokens_ristretto255::server::Server,
) {
    server
        .redeem_token(&key_store, &nonce_store, token)
        .await
        .unwrap();
}

pub fn criterion_batched_ristretto255_benchmark(c: &mut Criterion) {
    const NR: u16 = 100;
    // Key pair generation
    c.bench_function("BATCHED RISTRETTO255 SERVER: Generate key pair", move |b| {
        b.to_async(FuturesExecutor).iter_with_setup(
            || {
                let key_store = batched_memory_stores::MemoryKeyStoreRistretto255::default();
                let server = privacypass::batched_tokens_ristretto255::server::Server::new();
                (key_store, server)
            },
            |(key_store, server)| create_batched_keypair(key_store, server),
        );
    });

    // Issue token request
    c.bench_function(
        &format!("BATCHED RISTRETTO255 CLIENT: Issue token request for {NR} tokens"),
        move |b| {
            b.iter_with_setup(
                || {
                    let key_store = batched_memory_stores::MemoryKeyStoreRistretto255::default();
                    let server = privacypass::batched_tokens_ristretto255::server::Server::new();
                    let rt = Runtime::new().unwrap();
                    let public_key =
                        rt.block_on(async { server.create_keypair(&key_store).await.unwrap() });
                    let challenge = TokenChallenge::new(
                        TokenType::BatchedTokenRistretto255,
                        "example.com",
                        None,
                        &["example.com".to_string()],
                    );
                    (public_key, challenge)
                },
                |(public_key, challenge)| {
                    TokenRequest::new(public_key, &challenge, NR).unwrap();
                },
            );
        },
    );

    // Issue token response
    c.bench_function(
        &format!("BATCHED RISTRETTO255 SERVER: Issue token response for {NR} tokens"),
        move |b| {
            b.to_async(FuturesExecutor).iter_with_setup(
                || {
                    let key_store = batched_memory_stores::MemoryKeyStoreRistretto255::default();
                    let server = privacypass::batched_tokens_ristretto255::server::Server::new();
                    let rt = Runtime::new().unwrap();
                    let public_key =
                        rt.block_on(async { server.create_keypair(&key_store).await.unwrap() });
                    let challenge = TokenChallenge::new(
                        TokenType::BatchedTokenRistretto255,
                        "example.com",
                        None,
                        &["example.com".to_string()],
                    );
                    let (token_request, _token_state) =
                        TokenRequest::new(public_key, &challenge, NR).unwrap();
                    (key_store, server, token_request)
                },
                |(key_store, server, token_request)| {
                    issue_batched_token_response(key_store, server, token_request)
                },
            );
        },
    );

    // Issue token
    c.bench_function(
        &format!("BATCHED RISTRETTO255 CLIENT: Issue {NR} tokens"),
        move |b| {
            b.iter_with_setup(
                || {
                    let key_store = batched_memory_stores::MemoryKeyStoreRistretto255::default();
                    let server = privacypass::batched_tokens_ristretto255::server::Server::new();
                    let rt = Runtime::new().unwrap();
                    let public_key =
                        rt.block_on(async { server.create_keypair(&key_store).await.unwrap() });
                    let challenge = TokenChallenge::new(
                        TokenType::BatchedTokenRistretto255,
                        "example.com",
                        None,
                        &["example.com".to_string()],
                    );
                    let (token_request, token_state) =
                        TokenRequest::new(public_key, &challenge, NR).unwrap();
                    let token_response = rt.block_on(async {
                        server
                            .issue_token_response(&key_store, token_request)
                            .await
                            .unwrap()
                    });
                    (token_response, token_state)
                },
                |(token_response, token_state)| {
                    token_response.issue_tokens(&token_state).unwrap();
                },
            );
        },
    );

    // Redeem token
    c.bench_function("BATCHED RISTRETTO255 SERVER: Redeem token", move |b| {
        b.to_async(FuturesExecutor).iter_with_setup(
            || {
                let key_store = batched_memory_stores::MemoryKeyStoreRistretto255::default();
                let nonce_store = batched_memory_stores::MemoryNonceStore::default();
                let server = privacypass::batched_tokens_ristretto255::server::Server::new();
                let rt = Runtime::new().unwrap();
                let public_key =
                    rt.block_on(async { server.create_keypair(&key_store).await.unwrap() });
                let challenge = TokenChallenge::new(
                    TokenType::BatchedTokenRistretto255,
                    "example.com",
                    None,
                    &["example.com".to_string()],
                );
                let (token_request, token_state) =
                    TokenRequest::new(public_key, &challenge, NR).unwrap();
                let token_response = rt.block_on(async {
                    server
                        .issue_token_response(&key_store, token_request)
                        .await
                        .unwrap()
                });
                let tokens = token_response.issue_tokens(&token_state).unwrap();
                (key_store, nonce_store, tokens, server)
            },
            |(key_store, nonce_store, tokens, server)| {
                redeem_batched_token(key_store, nonce_store, tokens[0].clone(), server)
            },
        );
    });
}
