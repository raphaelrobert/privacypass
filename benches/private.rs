use criterion::{async_executor::FuturesExecutor, Criterion};
use generic_array::ArrayLength;
use tokio::runtime::Runtime;

use privacypass::{
    auth::authenticate::TokenChallenge, private_tokens::TokenRequest,
    test_utils::private_memory_stores, TokenType,
};

async fn create_private_keypair(
    key_store: private_memory_stores::MemoryKeyStore,
    server: privacypass::private_tokens::server::Server,
) {
    let _public_key = server.create_keypair(&key_store).await.unwrap();
}

async fn issue_private_token_response(
    key_store: private_memory_stores::MemoryKeyStore,
    server: privacypass::private_tokens::server::Server,
    token_request: privacypass::private_tokens::TokenRequest,
) -> privacypass::private_tokens::TokenResponse {
    server
        .issue_token_response(&key_store, token_request)
        .await
        .unwrap()
}

async fn redeem_private_token<Nk: ArrayLength<u8>>(
    key_store: private_memory_stores::MemoryKeyStore,
    nonce_store: private_memory_stores::MemoryNonceStore,
    token: privacypass::auth::authorize::Token<Nk>,
    server: privacypass::private_tokens::server::Server,
) {
    server
        .redeem_token(&key_store, &nonce_store, token)
        .await
        .unwrap();
}

pub fn criterion_private_benchmark(c: &mut Criterion) {
    // Key pair generation
    c.bench_function("PRIVATE SERVER: Generate key pair", move |b| {
        b.to_async(FuturesExecutor).iter_with_setup(
            || {
                let key_store = private_memory_stores::MemoryKeyStore::default();
                let server = privacypass::private_tokens::server::Server::new();
                (key_store, server)
            },
            |(key_store, server)| create_private_keypair(key_store, server),
        );
    });

    // Issue token request
    c.bench_function("PRIVATE CLIENT: Issue token request", move |b| {
        b.iter_with_setup(
            || {
                let key_store = private_memory_stores::MemoryKeyStore::default();
                let server = privacypass::private_tokens::server::Server::new();
                let rt = Runtime::new().unwrap();
                let public_key =
                    rt.block_on(async { server.create_keypair(&key_store).await.unwrap() });
                let challenge = TokenChallenge::new(
                    TokenType::PrivateToken,
                    "example.com",
                    None,
                    &["example.com".to_string()],
                );
                (public_key, challenge)
            },
            |(public_key, challenge)| {
                TokenRequest::new(public_key, &challenge).unwrap();
            },
        );
    });

    // Issue token response
    c.bench_function("PRIVATE SERVER: Issue token response", move |b| {
        b.to_async(FuturesExecutor).iter_with_setup(
            || {
                let key_store = private_memory_stores::MemoryKeyStore::default();
                let server = privacypass::private_tokens::server::Server::new();
                let rt = Runtime::new().unwrap();
                let public_key =
                    rt.block_on(async { server.create_keypair(&key_store).await.unwrap() });
                let challenge = TokenChallenge::new(
                    TokenType::PrivateToken,
                    "example.com",
                    None,
                    &["example.com".to_string()],
                );
                let (token_request, _token_state) =
                    TokenRequest::new(public_key, &challenge).unwrap();
                (key_store, server, token_request)
            },
            |(key_store, server, token_request)| {
                issue_private_token_response(key_store, server, token_request)
            },
        );
    });

    // Issue token
    c.bench_function("PRIVATE CLIENT: Issue token", move |b| {
        b.iter_with_setup(
            || {
                let key_store = private_memory_stores::MemoryKeyStore::default();
                let server = privacypass::private_tokens::server::Server::new();
                let rt = Runtime::new().unwrap();
                let public_key =
                    rt.block_on(async { server.create_keypair(&key_store).await.unwrap() });
                let challenge = TokenChallenge::new(
                    TokenType::PrivateToken,
                    "example.com",
                    None,
                    &["example.com".to_string()],
                );
                let (token_request, token_state) =
                    TokenRequest::new(public_key, &challenge).unwrap();
                let token_response = rt.block_on(async {
                    server
                        .issue_token_response(&key_store, token_request)
                        .await
                        .unwrap()
                });
                (token_response, token_state)
            },
            |(token_response, token_state)| {
                token_response.issue_token(&token_state).unwrap();
            },
        );
    });

    // Redeem token
    c.bench_function("PRIVATE SERVER: Redeem token", move |b| {
        b.to_async(FuturesExecutor).iter_with_setup(
            || {
                let key_store = private_memory_stores::MemoryKeyStore::default();
                let nonce_store = private_memory_stores::MemoryNonceStore::default();
                let server = privacypass::private_tokens::server::Server::new();
                let rt = Runtime::new().unwrap();
                let public_key =
                    rt.block_on(async { server.create_keypair(&key_store).await.unwrap() });
                let challenge = TokenChallenge::new(
                    TokenType::PrivateToken,
                    "example.com",
                    None,
                    &["example.com".to_string()],
                );
                let (token_request, token_state) =
                    TokenRequest::new(public_key, &challenge).unwrap();
                let token_response = rt.block_on(async {
                    server
                        .issue_token_response(&key_store, token_request)
                        .await
                        .unwrap()
                });
                let token = token_response.issue_token(&token_state).unwrap();
                (key_store, nonce_store, token, server)
            },
            |(key_store, nonce_store, token, server)| {
                redeem_private_token(key_store, nonce_store, token, server)
            },
        );
    });
}
