use privacypass::public_tokens::server::OriginKeyStore;
#[path = "../tests/public_memory_stores.rs"]
mod public_memory_stores;

use criterion::{async_executor::FuturesExecutor, Criterion};
use generic_array::ArrayLength;
use tokio::runtime::Runtime;

use privacypass::{auth::authenticate::TokenChallenge, TokenType};

async fn create_public_keypair(
    mut issuer_key_store: public_memory_stores::IssuerMemoryKeyStore,
    mut server: privacypass::public_tokens::server::IssuerServer,
) {
    let _public_key = server
        .create_keypair(&mut issuer_key_store, 1)
        .await
        .unwrap();
}

async fn issue_public_token_response(
    issuer_key_store: public_memory_stores::IssuerMemoryKeyStore,
    mut server: privacypass::public_tokens::server::IssuerServer,
    token_request: privacypass::public_tokens::TokenRequest,
) -> privacypass::public_tokens::TokenResponse {
    server
        .issue_token_response(&issuer_key_store, token_request)
        .await
        .unwrap()
}

async fn redeem_public_token<Nk: ArrayLength<u8>>(
    mut origin_key_store: public_memory_stores::OriginMemoryKeyStore,
    mut nonce_store: public_memory_stores::MemoryNonceStore,
    token: privacypass::auth::authorize::Token<Nk>,
    mut origin_server: privacypass::public_tokens::server::OriginServer,
) {
    origin_server
        .redeem_token(&mut origin_key_store, &mut nonce_store, token)
        .await
        .unwrap();
}

pub fn criterion_public_benchmark(c: &mut Criterion) {
    // Key pair generation
    c.bench_function("PUBLIC SERVER: Generate key pair", move |b| {
        b.to_async(FuturesExecutor).iter_with_setup(
            || {
                let key_store = public_memory_stores::IssuerMemoryKeyStore::default();
                let server = privacypass::public_tokens::server::IssuerServer::new();
                (key_store, server)
            },
            |(key_store, server)| create_public_keypair(key_store, server),
        );
    });

    // Issue token request
    c.bench_function("PUBLIC CLIENT: Issue token request", move |b| {
        b.iter_with_setup(
            || {
                let mut key_store = public_memory_stores::IssuerMemoryKeyStore::default();
                let mut server = privacypass::public_tokens::server::IssuerServer::new();
                let rt = Runtime::new().unwrap();
                let key_pair =
                    rt.block_on(async { server.create_keypair(&mut key_store, 1).await.unwrap() });
                let client = privacypass::public_tokens::client::Client::new(1, key_pair.pk);
                let challenge = TokenChallenge::new(
                    TokenType::Public,
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
                let mut key_store = public_memory_stores::IssuerMemoryKeyStore::default();
                let mut server = privacypass::public_tokens::server::IssuerServer::new();
                let rt = Runtime::new().unwrap();
                let key_pair =
                    rt.block_on(async { server.create_keypair(&mut key_store, 1).await.unwrap() });
                let mut client = privacypass::public_tokens::client::Client::new(1, key_pair.pk);
                let challenge = TokenChallenge::new(
                    TokenType::Public,
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
                let mut key_store = public_memory_stores::IssuerMemoryKeyStore::default();
                let mut server = privacypass::public_tokens::server::IssuerServer::new();
                let rt = Runtime::new().unwrap();
                let key_pair =
                    rt.block_on(async { server.create_keypair(&mut key_store, 1).await.unwrap() });
                let mut client = privacypass::public_tokens::client::Client::new(1, key_pair.pk);
                let challenge = TokenChallenge::new(
                    TokenType::Public,
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
                let mut issuer_key_store = public_memory_stores::IssuerMemoryKeyStore::default();
                let mut origin_key_store = public_memory_stores::OriginMemoryKeyStore::default();
                let nonce_store = public_memory_stores::MemoryNonceStore::default();
                let mut issuer_server = privacypass::public_tokens::server::IssuerServer::new();
                let origin_server = privacypass::public_tokens::server::OriginServer::new();
                let rt = Runtime::new().unwrap();
                let key_pair = rt.block_on(async {
                    let key_pair = issuer_server
                        .create_keypair(&mut issuer_key_store, 1)
                        .await
                        .unwrap();
                    origin_key_store.insert(1, key_pair.pk.clone()).await;
                    key_pair
                });
                let mut client = privacypass::public_tokens::client::Client::new(1, key_pair.pk);
                let challenge = TokenChallenge::new(
                    TokenType::Public,
                    "example.com",
                    None,
                    vec!["example.com".to_string()],
                );
                let (token_request, token_state) = client.issue_token_request(&challenge).unwrap();
                let token_response = rt.block_on(async {
                    issuer_server
                        .issue_token_response(&issuer_key_store, token_request)
                        .await
                        .unwrap()
                });
                let token = client.issue_token(token_response, token_state).unwrap();
                (origin_key_store, nonce_store, token, origin_server)
            },
            |(origin_key_store, nonce_store, token, origin_server)| {
                redeem_public_token(origin_key_store, nonce_store, token, origin_server)
            },
        );
    });
}
