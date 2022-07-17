#[path = "../tests/memory_stores.rs"]
mod memory_stores;

use memory_stores::*;

use criterion::{async_executor::FuturesExecutor, criterion_group, criterion_main, Criterion};
use tokio::runtime::Runtime;
use voprf::*;

use privacypass::{
    auth::TokenChallenge,
    private_tokens::{client::*, server::*, Token, TokenRequest, TokenResponse},
    TokenType,
};

async fn create_keypair(
    mut key_store: MemoryKeyStore<Ristretto255>,
    mut server: Server<Ristretto255>,
) {
    let _public_key = server.create_keypair(&mut key_store, 1).await.unwrap();
}

async fn issue_token_response(
    key_store: MemoryKeyStore<Ristretto255>,
    mut server: Server<Ristretto255>,
    token_request: TokenRequest,
) -> TokenResponse {
    server
        .issue_token_response(&key_store, token_request)
        .await
        .unwrap()
}

async fn redeem_token(
    mut key_store: MemoryKeyStore<Ristretto255>,
    mut nonce_store: MemoryNonceStore,
    token: Token,
    mut server: Server<Ristretto255>,
) {
    server
        .redeem_token(&mut key_store, &mut nonce_store, token)
        .await
        .unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    // Key pair generation
    c.bench_function("SERVER: Generate key pair", move |b| {
        b.to_async(FuturesExecutor).iter_with_setup(
            || {
                let key_store = MemoryKeyStore::default();
                let server = Server::<Ristretto255>::new();
                (key_store, server)
            },
            |(key_store, server)| create_keypair(key_store, server),
        );
    });

    // Issue token request
    c.bench_function("CLIENT: Issue token request", move |b| {
        b.iter_with_setup(
            || {
                let mut key_store = MemoryKeyStore::default();
                let mut server = Server::<Ristretto255>::new();
                let rt = Runtime::new().unwrap();
                let public_key =
                    rt.block_on(async { server.create_keypair(&mut key_store, 1).await.unwrap() });
                let client = Client::<Ristretto255>::new(1, public_key);
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
                let mut key_store = MemoryKeyStore::default();
                let mut server = Server::<Ristretto255>::new();
                let rt = Runtime::new().unwrap();
                let public_key =
                    rt.block_on(async { server.create_keypair(&mut key_store, 1).await.unwrap() });
                let mut client = Client::<Ristretto255>::new(1, public_key);
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
                issue_token_response(key_store, server, token_request)
            },
        );
    });

    // Issue token
    c.bench_function("CLIENT: Issue token", move |b| {
        b.iter_with_setup(
            || {
                let mut key_store = MemoryKeyStore::default();
                let mut server = Server::<Ristretto255>::new();
                let rt = Runtime::new().unwrap();
                let public_key =
                    rt.block_on(async { server.create_keypair(&mut key_store, 1).await.unwrap() });
                let mut client = Client::<Ristretto255>::new(1, public_key);
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
                let mut key_store = MemoryKeyStore::default();
                let nonce_store = MemoryNonceStore::default();
                let mut server = Server::<Ristretto255>::new();
                let rt = Runtime::new().unwrap();
                let public_key =
                    rt.block_on(async { server.create_keypair(&mut key_store, 1).await.unwrap() });
                let mut client = Client::<Ristretto255>::new(1, public_key);
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
                redeem_token(key_store, nonce_store, token, server)
            },
        );
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
