#[path = "../tests/private_memory_stores.rs"]
mod private_memory_stores;

use criterion::{async_executor::FuturesExecutor, Criterion};
use tokio::runtime::Runtime;
use voprf::*;

use privacypass::{auth::TokenChallenge, TokenType};

async fn create_private_keypair(
    mut key_store: private_memory_stores::MemoryKeyStore<Ristretto255>,
    mut server: privacypass::private_tokens::server::Server<Ristretto255>,
) {
    let _public_key = server.create_keypair(&mut key_store, 1).await.unwrap();
}

async fn issue_private_token_response(
    key_store: private_memory_stores::MemoryKeyStore<Ristretto255>,
    mut server: privacypass::private_tokens::server::Server<Ristretto255>,
    token_request: privacypass::private_tokens::TokenRequest,
) -> privacypass::private_tokens::TokenResponse {
    server
        .issue_token_response(&key_store, token_request)
        .await
        .unwrap()
}

async fn redeem_private_token(
    mut key_store: private_memory_stores::MemoryKeyStore<Ristretto255>,
    mut nonce_store: private_memory_stores::MemoryNonceStore,
    token: privacypass::private_tokens::Token,
    mut server: privacypass::private_tokens::server::Server<Ristretto255>,
) {
    server
        .redeem_token(&mut key_store, &mut nonce_store, token)
        .await
        .unwrap();
}

pub fn criterion_private_benchmark(c: &mut Criterion) {
    // Key pair generation
    c.bench_function("PRIVATE SERVER: Generate key pair", move |b| {
        b.to_async(FuturesExecutor).iter_with_setup(
            || {
                let key_store = private_memory_stores::MemoryKeyStore::default();
                let server = privacypass::private_tokens::server::Server::<Ristretto255>::new();
                (key_store, server)
            },
            |(key_store, server)| create_private_keypair(key_store, server),
        );
    });

    // Issue token request
    c.bench_function("PRIVATE CLIENT: Issue token request", move |b| {
        b.iter_with_setup(
            || {
                let mut key_store = private_memory_stores::MemoryKeyStore::default();
                let mut server = privacypass::private_tokens::server::Server::<Ristretto255>::new();
                let rt = Runtime::new().unwrap();
                let public_key =
                    rt.block_on(async { server.create_keypair(&mut key_store, 1).await.unwrap() });
                let client =
                    privacypass::private_tokens::client::Client::<Ristretto255>::new(1, public_key);
                let challenge = TokenChallenge::new(
                    TokenType::Voprf,
                    "example.com",
                    None,
                    vec!["example.com".to_string()],
                );
                (client, challenge)
            },
            |(mut client, challenge)| {
                client.issue_token_request(&challenge).unwrap();
            },
        );
    });

    // Issue token response
    c.bench_function("PRIVATE SERVER: Issue token response", move |b| {
        b.to_async(FuturesExecutor).iter_with_setup(
            || {
                let mut key_store = private_memory_stores::MemoryKeyStore::default();
                let mut server = privacypass::private_tokens::server::Server::<Ristretto255>::new();
                let rt = Runtime::new().unwrap();
                let public_key =
                    rt.block_on(async { server.create_keypair(&mut key_store, 1).await.unwrap() });
                let mut client =
                    privacypass::private_tokens::client::Client::<Ristretto255>::new(1, public_key);
                let challenge = TokenChallenge::new(
                    TokenType::Voprf,
                    "example.com",
                    None,
                    vec!["example.com".to_string()],
                );
                let (token_request, _token_state) = client.issue_token_request(&challenge).unwrap();
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
                let mut key_store = private_memory_stores::MemoryKeyStore::default();
                let mut server = privacypass::private_tokens::server::Server::<Ristretto255>::new();
                let rt = Runtime::new().unwrap();
                let public_key =
                    rt.block_on(async { server.create_keypair(&mut key_store, 1).await.unwrap() });
                let mut client =
                    privacypass::private_tokens::client::Client::<Ristretto255>::new(1, public_key);
                let challenge = TokenChallenge::new(
                    TokenType::Voprf,
                    "example.com",
                    None,
                    vec!["example.com".to_string()],
                );
                let (token_request, token_state) = client.issue_token_request(&challenge).unwrap();
                let token_response = rt.block_on(async {
                    server
                        .issue_token_response(&key_store, token_request)
                        .await
                        .unwrap()
                });
                (client, token_response, token_state)
            },
            |(client, token_response, token_state)| {
                client.issue_token(token_response, token_state).unwrap();
            },
        );
    });

    // Redeem token
    c.bench_function("PRIVATE SERVER: Redeem token", move |b| {
        b.to_async(FuturesExecutor).iter_with_setup(
            || {
                let mut key_store = private_memory_stores::MemoryKeyStore::default();
                let nonce_store = private_memory_stores::MemoryNonceStore::default();
                let mut server = privacypass::private_tokens::server::Server::<Ristretto255>::new();
                let rt = Runtime::new().unwrap();
                let public_key =
                    rt.block_on(async { server.create_keypair(&mut key_store, 1).await.unwrap() });
                let mut client =
                    privacypass::private_tokens::client::Client::<Ristretto255>::new(1, public_key);
                let challenge = TokenChallenge::new(
                    TokenType::Voprf,
                    "example.com",
                    None,
                    vec!["example.com".to_string()],
                );
                let (token_request, token_state) = client.issue_token_request(&challenge).unwrap();
                let token_response = rt.block_on(async {
                    server
                        .issue_token_response(&key_store, token_request)
                        .await
                        .unwrap()
                });
                let token = client.issue_token(token_response, token_state).unwrap();
                (key_store, nonce_store, token, server)
            },
            |(key_store, nonce_store, token, server)| {
                redeem_private_token(key_store, nonce_store, token, server)
            },
        );
    });
}
