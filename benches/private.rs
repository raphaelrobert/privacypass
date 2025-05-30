use criterion::{Criterion, async_executor::FuturesExecutor};
use generic_array::ArrayLength;
use p384::NistP384;
use tokio::runtime::Runtime;

use privacypass::{
    auth::{authenticate::TokenChallenge, authorize::Token},
    common::private::PrivateCipherSuite,
    private_tokens::{TokenRequest, TokenResponse, server::Server},
    test_utils::{nonce_store::MemoryNonceStore, private_memory_store::MemoryKeyStoreVoprf},
};
use voprf::Ristretto255;

async fn create_private_keypair<CS: PrivateCipherSuite>(
    key_store: MemoryKeyStoreVoprf<CS>,
    server: Server<CS>,
) {
    let _public_key = server.create_keypair(&key_store).await.unwrap();
}

async fn issue_private_token_response<CS: PrivateCipherSuite>(
    key_store: MemoryKeyStoreVoprf<CS>,
    server: Server<CS>,
    token_request: TokenRequest<CS>,
) -> TokenResponse<CS> {
    server
        .issue_token_response(&key_store, token_request)
        .await
        .unwrap()
}

async fn redeem_private_token<Nk: ArrayLength<u8>, CS: PrivateCipherSuite>(
    key_store: MemoryKeyStoreVoprf<CS>,
    nonce_store: MemoryNonceStore,
    token: Token<Nk>,
    server: Server<CS>,
) {
    server
        .redeem_token(&key_store, &nonce_store, token)
        .await
        .unwrap();
}

pub fn criterion_private_p384_benchmark(c: &mut Criterion) {
    flow::<NistP384>(c);
}

pub fn criterion_private_ristretto255_benchmark(c: &mut Criterion) {
    flow::<Ristretto255>(c);
}

pub fn flow<CS: PrivateCipherSuite>(c: &mut Criterion) {
    // Key pair generation
    c.bench_function(
        &format!("PRIVATE SERVER ({}): Generate key pair", CS::ID),
        move |b| {
            b.to_async(FuturesExecutor).iter_with_setup(
                || {
                    let key_store = MemoryKeyStoreVoprf::<CS>::default();
                    let server = privacypass::private_tokens::server::Server::new();
                    (key_store, server)
                },
                |(key_store, server)| create_private_keypair(key_store, server),
            );
        },
    );

    // Issue token request
    c.bench_function(
        &format!("PRIVATE CLIENT ({}): Issue token request", CS::ID),
        move |b| {
            b.iter_with_setup(
                || {
                    let key_store = MemoryKeyStoreVoprf::<CS>::default();
                    let server = privacypass::private_tokens::server::Server::new();
                    let rt = Runtime::new().unwrap();
                    let public_key =
                        rt.block_on(async { server.create_keypair(&key_store).await.unwrap() });
                    let challenge = TokenChallenge::new(
                        CS::token_type(),
                        "example.com",
                        None,
                        &["example.com".to_string()],
                    );
                    (public_key, challenge)
                },
                |(public_key, challenge)| {
                    TokenRequest::<CS>::new(public_key, &challenge).unwrap();
                },
            );
        },
    );

    // Issue token response
    c.bench_function(
        &format!("PRIVATE SERVER ({}): Issue token response", CS::ID),
        move |b| {
            b.to_async(FuturesExecutor).iter_with_setup(
                || {
                    let key_store = MemoryKeyStoreVoprf::<CS>::default();
                    let server = privacypass::private_tokens::server::Server::new();
                    let rt = Runtime::new().unwrap();
                    let public_key =
                        rt.block_on(async { server.create_keypair(&key_store).await.unwrap() });
                    let challenge = TokenChallenge::new(
                        CS::token_type(),
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
        },
    );

    // Issue token
    c.bench_function(
        &format!("PRIVATE CLIENT ({}): Issue token", CS::ID),
        move |b| {
            b.iter_with_setup(
                || {
                    let key_store = MemoryKeyStoreVoprf::<CS>::default();
                    let server = privacypass::private_tokens::server::Server::new();
                    let rt = Runtime::new().unwrap();
                    let public_key =
                        rt.block_on(async { server.create_keypair(&key_store).await.unwrap() });
                    let challenge = TokenChallenge::new(
                        CS::token_type(),
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
        },
    );

    // Redeem token
    c.bench_function(
        &format!("PRIVATE SERVER ({}): Redeem token", CS::ID),
        move |b| {
            b.to_async(FuturesExecutor).iter_with_setup(
                || {
                    let key_store = MemoryKeyStoreVoprf::<CS>::default();
                    let nonce_store = MemoryNonceStore::default();
                    let server = privacypass::private_tokens::server::Server::new();
                    let rt = Runtime::new().unwrap();
                    let public_key =
                        rt.block_on(async { server.create_keypair(&key_store).await.unwrap() });
                    let challenge = TokenChallenge::new(
                        CS::token_type(),
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
        },
    );
}
