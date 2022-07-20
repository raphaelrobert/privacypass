#[path = "../tests/private_memory_stores.rs"]
mod private_memory_stores;

#[path = "../tests/public_memory_stores.rs"]
mod public_memory_stores;

use criterion::{async_executor::FuturesExecutor, criterion_group, criterion_main, Criterion};
use tokio::runtime::Runtime;
use voprf::*;

use privacypass::{auth::TokenChallenge, TokenType};

async fn create_private_keypair(
    mut key_store: private_memory_stores::MemoryKeyStore<Ristretto255>,
    mut server: privacypass::private_tokens::server::Server<Ristretto255>,
) {
    let _public_key = server.create_keypair(&mut key_store, 1).await.unwrap();
}

async fn create_public_keypair(
    mut key_store: public_memory_stores::MemoryKeyStore,
    mut server: privacypass::public_tokens::server::Server,
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

async fn issue_public_token_response(
    key_store: public_memory_stores::MemoryKeyStore,
    mut server: privacypass::public_tokens::server::Server,
    token_request: privacypass::public_tokens::TokenRequest,
) -> privacypass::public_tokens::TokenResponse {
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

async fn redeem_public_token(
    mut key_store: public_memory_stores::MemoryKeyStore,
    mut nonce_store: public_memory_stores::MemoryNonceStore,
    token: privacypass::public_tokens::Token,
    mut server: privacypass::public_tokens::server::Server,
) {
    server
        .redeem_token(&mut key_store, &mut nonce_store, token)
        .await
        .unwrap();
}

fn criterion_private_benchmark(c: &mut Criterion) {
    // Key pair generation
    c.bench_function("SERVER: Generate key pair", move |b| {
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
    c.bench_function("CLIENT: Issue token request", move |b| {
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
    c.bench_function("SERVER: Issue token response", move |b| {
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
    c.bench_function("CLIENT: Issue token", move |b| {
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
    c.bench_function("Server: Redeem token", move |b| {
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

fn criterion_public_benchmark(c: &mut Criterion) {
    // Key pair generation
    c.bench_function("PUBLIC SERVER: Generate key pair", move |b| {
        b.to_async(FuturesExecutor).iter_with_setup(
            || {
                let key_store = public_memory_stores::MemoryKeyStore::default();
                let server = privacypass::public_tokens::server::Server::new();
                (key_store, server)
            },
            |(key_store, server)| create_public_keypair(key_store, server),
        );
    });

    // Issue token request
    c.bench_function("PUBLIC CLIENT: Issue token request", move |b| {
        b.iter_with_setup(
            || {
                let mut key_store = public_memory_stores::MemoryKeyStore::default();
                let mut server = privacypass::public_tokens::server::Server::new();
                let rt = Runtime::new().unwrap();
                let key_pair =
                    rt.block_on(async { server.create_keypair(&mut key_store, 1).await.unwrap() });
                let client = privacypass::public_tokens::client::Client::new(1, key_pair.pk);
                let challenge = TokenChallenge::new(
                    TokenType::BlindRSA,
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
    c.bench_function("PUBLIC SERVER: Issue token response", move |b| {
        b.to_async(FuturesExecutor).iter_with_setup(
            || {
                let mut key_store = public_memory_stores::MemoryKeyStore::default();
                let mut server = privacypass::public_tokens::server::Server::new();
                let rt = Runtime::new().unwrap();
                let key_pair =
                    rt.block_on(async { server.create_keypair(&mut key_store, 1).await.unwrap() });
                let mut client = privacypass::public_tokens::client::Client::new(1, key_pair.pk);
                let challenge = TokenChallenge::new(
                    TokenType::BlindRSA,
                    "example.com",
                    None,
                    vec!["example.com".to_string()],
                );
                let (token_request, _token_state) = client.issue_token_request(&challenge).unwrap();
                (key_store, server, token_request)
            },
            |(key_store, server, token_request)| {
                issue_public_token_response(key_store, server, token_request)
            },
        );
    });

    // Issue token
    c.bench_function("PUBLIC CLIENT: Issue token", move |b| {
        b.iter_with_setup(
            || {
                let mut key_store = public_memory_stores::MemoryKeyStore::default();
                let mut server = privacypass::public_tokens::server::Server::new();
                let rt = Runtime::new().unwrap();
                let key_pair =
                    rt.block_on(async { server.create_keypair(&mut key_store, 1).await.unwrap() });
                let mut client = privacypass::public_tokens::client::Client::new(1, key_pair.pk);
                let challenge = TokenChallenge::new(
                    TokenType::BlindRSA,
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
    c.bench_function("PUBLIC SERVER: Redeem token", move |b| {
        b.to_async(FuturesExecutor).iter_with_setup(
            || {
                let mut key_store = public_memory_stores::MemoryKeyStore::default();
                let nonce_store = public_memory_stores::MemoryNonceStore::default();
                let mut server = privacypass::public_tokens::server::Server::new();
                let rt = Runtime::new().unwrap();
                let key_pair =
                    rt.block_on(async { server.create_keypair(&mut key_store, 1).await.unwrap() });
                let mut client = privacypass::public_tokens::client::Client::new(1, key_pair.pk);
                let challenge = TokenChallenge::new(
                    TokenType::BlindRSA,
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
                redeem_public_token(key_store, nonce_store, token, server)
            },
        );
    });
}

criterion_group!(
    benches,
    criterion_private_benchmark,
    criterion_public_benchmark
);
criterion_main!(benches);
