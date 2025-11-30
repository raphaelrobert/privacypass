use privacypass::{
    public_tokens::{
        TokenRequest, public_key_to_truncated_token_key_id,
        server::{IssuerServer, OriginKeyStore, OriginServer},
    },
    test_utils::{
        nonce_store::MemoryNonceStore,
        public_memory_store::{self, IssuerMemoryKeyStore, OriginMemoryKeyStore},
    },
};

use criterion::{Criterion, async_executor::FuturesExecutor};
use generic_array::ArrayLength;
use rand::{CryptoRng, RngCore};
use tokio::runtime::Runtime;

use privacypass::{TokenType, auth::authenticate::TokenChallenge};

async fn create_public_keypair<R: RngCore + CryptoRng>(
    rng: &mut R,
    key_store: public_memory_store::IssuerMemoryKeyStore,
    server: privacypass::public_tokens::server::IssuerServer,
) {
    let _public_key = server.create_keypair(rng, &key_store).await.unwrap();
}

async fn issue_public_token_response(
    issuer_key_store: public_memory_store::IssuerMemoryKeyStore,
    server: privacypass::public_tokens::server::IssuerServer,
    token_request: privacypass::public_tokens::TokenRequest,
) -> privacypass::public_tokens::TokenResponse {
    server
        .issue_token_response(&issuer_key_store, token_request)
        .await
        .unwrap()
}

async fn redeem_public_token<Nk: ArrayLength>(
    origin_key_store: public_memory_store::OriginMemoryKeyStore,
    nonce_store: MemoryNonceStore,
    token: privacypass::auth::authorize::Token<Nk>,
    origin_server: privacypass::public_tokens::server::OriginServer,
) {
    origin_server
        .redeem_token(&origin_key_store, &nonce_store, token)
        .await
        .unwrap();
}

pub fn criterion_public_benchmark(c: &mut Criterion) {
    // Key pair generation
    c.bench_function("PUBLIC SERVER: Generate key pair", move |b| {
        b.to_async(FuturesExecutor).iter_with_setup(
            || {
                let rng = rand::thread_rng();
                let key_store = IssuerMemoryKeyStore::default();
                let server = IssuerServer::new();
                (rng, key_store, server)
            },
            |(mut rng, key_store, server)| async move {
                create_public_keypair(&mut rng, key_store, server).await;
            },
        );
    });

    // Issue token request
    c.bench_function("PUBLIC CLIENT: Issue token request", move |b| {
        b.iter_with_setup(
            || {
                let mut rng = rand::thread_rng();
                let key_store = IssuerMemoryKeyStore::default();
                let server = IssuerServer::new();

                let rt = Runtime::new().unwrap();
                let public_key = rt
                    .block_on(async { server.create_keypair(&mut rng, &key_store).await.unwrap() });
                let token_challenge = TokenChallenge::new(
                    TokenType::Public,
                    "example.com",
                    None,
                    &["example.com".to_string()],
                );
                (rng, public_key, token_challenge)
            },
            |(mut rng, public_key, token_challenge)| {
                TokenRequest::new(&mut rng, public_key, &token_challenge).unwrap();
            },
        );
    });

    // Issue token response
    c.bench_function("PUBLIC SERVER: Issue token response", move |b| {
        b.to_async(FuturesExecutor).iter_with_setup(
            || {
                let rng = &mut rand::thread_rng();
                let key_store = IssuerMemoryKeyStore::default();
                let server = IssuerServer::new();

                let rt = Runtime::new().unwrap();
                let public_key =
                    rt.block_on(async { server.create_keypair(rng, &key_store).await.unwrap() });
                let token_challenge = TokenChallenge::new(
                    TokenType::Public,
                    "example.com",
                    None,
                    &["example.com".to_string()],
                );
                let (token_request, _token_state) =
                    TokenRequest::new(rng, public_key, &token_challenge).unwrap();
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
                let rng = &mut rand::thread_rng();
                let key_store = IssuerMemoryKeyStore::default();
                let server = IssuerServer::new();

                let rt = Runtime::new().unwrap();
                let public_key =
                    rt.block_on(async { server.create_keypair(rng, &key_store).await.unwrap() });
                let token_challenge = TokenChallenge::new(
                    TokenType::Public,
                    "example.com",
                    None,
                    &["example.com".to_string()],
                );
                let (token_request, token_state) =
                    TokenRequest::new(rng, public_key, &token_challenge).unwrap();
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
    c.bench_function("PUBLIC SERVER: Redeem token", move |b| {
        b.to_async(FuturesExecutor).iter_with_setup(
            || {
                let rng = &mut rand::thread_rng();
                let issuer_key_store = IssuerMemoryKeyStore::default();
                let origin_key_store = OriginMemoryKeyStore::default();

                let nonce_store = MemoryNonceStore::default();
                let issuer_server = IssuerServer::new();
                let origin_server = OriginServer::new();
                let rt = Runtime::new().unwrap();
                let public_key = rt.block_on(async {
                    let public_key = issuer_server
                        .create_keypair(rng, &issuer_key_store)
                        .await
                        .unwrap();
                    origin_key_store
                        .insert(
                            public_key_to_truncated_token_key_id(&public_key),
                            public_key.clone(),
                        )
                        .await;
                    public_key
                });

                let token_challenge = TokenChallenge::new(
                    TokenType::Public,
                    "example.com",
                    None,
                    &["example.com".to_string()],
                );
                let (token_request, token_state) =
                    TokenRequest::new(rng, public_key, &token_challenge).unwrap();
                let token_response = rt.block_on(async {
                    issuer_server
                        .issue_token_response(&issuer_key_store, token_request)
                        .await
                        .unwrap()
                });
                let token = token_response.issue_token(&token_state).unwrap();
                (origin_key_store, nonce_store, token, origin_server)
            },
            |(origin_key_store, nonce_store, token, origin_server)| {
                redeem_public_token(origin_key_store, nonce_store, token, origin_server)
            },
        );
    });
}
