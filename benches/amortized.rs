use criterion::{Criterion, async_executor::FuturesExecutor};
use p384::NistP384;
use tokio::runtime::Runtime;

use privacypass::{
    amortized_tokens::{
        AmortizedBatchTokenRequest, AmortizedBatchTokenResponse, AmortizedToken, server::Server,
    },
    auth::authenticate::TokenChallenge,
    common::private::PPCipherSuite,
    test_utils::{nonce_store::MemoryNonceStore, private_memory_store::MemoryKeyStoreVoprf},
};
use voprf::Ristretto255;

async fn create_amortized_keypair<CS: PPCipherSuite>(
    key_store: MemoryKeyStoreVoprf<CS>,
    server: Server<CS>,
) {
    let _public_key = server.create_keypair(&key_store).await.unwrap();
}

async fn issue_amortized_token_response<CS: PPCipherSuite>(
    key_store: MemoryKeyStoreVoprf<CS>,
    server: Server<CS>,
    token_request: AmortizedBatchTokenRequest<CS>,
) -> AmortizedBatchTokenResponse<CS> {
    server
        .issue_token_response(&key_store, token_request)
        .await
        .unwrap()
}

async fn redeem_amortized_token<CS: PPCipherSuite>(
    key_store: MemoryKeyStoreVoprf<CS>,
    nonce_store: MemoryNonceStore,
    token: AmortizedToken<CS>,
    server: Server<CS>,
) {
    server
        .redeem_token(&key_store, &nonce_store, token)
        .await
        .unwrap();
}

pub fn criterion_amortized_p384_benchmark(c: &mut Criterion) {
    flow::<NistP384>(c);
}

pub fn criterion_amortized_ristretto255_benchmark(c: &mut Criterion) {
    flow::<Ristretto255>(c);
}

pub fn flow<CS: PPCipherSuite>(c: &mut Criterion) {
    const NR: u16 = 100;
    // Key pair generation
    c.bench_function(
        &format!("AMORTIZED SERVER ({}): Generate key pair", CS::ID),
        move |b| {
            b.to_async(FuturesExecutor).iter_with_setup(
                || {
                    let key_store = MemoryKeyStoreVoprf::<CS>::default();
                    let server = Server::new();
                    (key_store, server)
                },
                |(key_store, server)| create_amortized_keypair(key_store, server),
            );
        },
    );

    // Issue token request
    c.bench_function(
        &format!(
            "AMORTIZED CLIENT ({}): Issue token request for {NR} tokens",
            CS::ID
        ),
        move |b| {
            b.iter_with_setup(
                || {
                    let key_store = MemoryKeyStoreVoprf::<CS>::default();
                    let server = Server::new();
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
                    AmortizedBatchTokenRequest::<CS>::new(public_key, &challenge, NR).unwrap();
                },
            );
        },
    );

    // Issue token response
    c.bench_function(
        &format!(
            "AMORTIZED SERVER ({}): Issue token response for {NR} tokens",
            CS::ID
        ),
        move |b| {
            b.to_async(FuturesExecutor).iter_with_setup(
                || {
                    let key_store = MemoryKeyStoreVoprf::<CS>::default();
                    let server = Server::new();
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
                        AmortizedBatchTokenRequest::new(public_key, &challenge, NR).unwrap();
                    (key_store, server, token_request)
                },
                |(key_store, server, token_request)| {
                    issue_amortized_token_response(key_store, server, token_request)
                },
            );
        },
    );

    // Issue token
    c.bench_function(
        &format!("AMORTIZED CLIENT ({}): Issue {NR} tokens", CS::ID),
        move |b| {
            b.iter_with_setup(
                || {
                    let key_store = MemoryKeyStoreVoprf::<CS>::default();
                    let server = Server::new();
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
                        AmortizedBatchTokenRequest::new(public_key, &challenge, NR).unwrap();
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
    c.bench_function(
        &format!("AMORTIZED SERVER ({}): Redeem token", CS::ID),
        move |b| {
            b.to_async(FuturesExecutor).iter_with_setup(
                || {
                    let key_store = MemoryKeyStoreVoprf::<CS>::default();
                    let nonce_store = MemoryNonceStore::default();
                    let server = Server::new();
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
                        AmortizedBatchTokenRequest::new(public_key, &challenge, NR).unwrap();
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
                    redeem_amortized_token(key_store, nonce_store, tokens[0].clone(), server)
                },
            );
        },
    );
}
