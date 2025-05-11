use std::{fs::File, io::Write};

use generic_array::GenericArray;
use p384::NistP384;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};

use tls_codec::{Deserialize as _, Serialize as TlsSerializeTrait};
use voprf::{Group, Mode, Ristretto255, derive_key};

use privacypass::{
    PPCipherSuite,
    auth::authenticate::TokenChallenge,
    batched_tokens::{TokenRequest, TokenResponse, server::*},
    common::private::serialize_public_key,
    test_utils::{nonce_store::MemoryNonceStore, private_memory_store::MemoryKeyStoreVoprf},
};

#[derive(Serialize, Deserialize)]
struct BatchedTokenTestVector {
    #[serde(with = "hex", alias = "skS")]
    sk_s: Vec<u8>,
    #[serde(with = "hex", alias = "pkS")]
    pk_s: Vec<u8>,
    #[serde(with = "hex")]
    token_challenge: Vec<u8>,
    nonces: Vec<HexNonce>,
    blinds: Vec<HexBlind>,
    #[serde(with = "hex")]
    token_request: Vec<u8>,
    #[serde(with = "hex")]
    token_response: Vec<u8>,
    tokens: Vec<HexToken>,
}

#[derive(Serialize, Deserialize)]
struct HexNonce(#[serde(with = "hex")] Vec<u8>);

#[derive(Serialize, Deserialize)]
struct HexBlind(#[serde(with = "hex")] Vec<u8>);

#[derive(Serialize, Deserialize)]
struct HexToken(#[serde(with = "hex")] Vec<u8>);

#[tokio::test]
async fn read_kat_batched_token() {
    // === Check own KAT vectors ===

    // P384
    let list: Vec<BatchedTokenTestVector> =
        serde_json::from_str(include_str!("kat_vectors/batched_p384_rs.json").trim()).unwrap();
    evaluate_kat::<NistP384>(list).await;

    // Ristretto255
    let list: Vec<BatchedTokenTestVector> =
        serde_json::from_str(include_str!("kat_vectors/batched_ristretto255_rs.json").trim())
            .unwrap();
    evaluate_kat::<Ristretto255>(list).await;

    // Check KAT vectors from the Go implementation

    // Ristretto255

    // TODO: Uncomment when Go implementation is fixed
    /* let list: Vec<BatchedTokenTestVector> = serde_json::from_str(
        include_str!("kat_vectors/batched_ristretto255_go.json").trim(),
    )
    .unwrap();
    evaluate_kat::<Ristretto255>(list).await; */
}

async fn evaluate_kat<CS: PPCipherSuite>(list: Vec<BatchedTokenTestVector>) {
    for vector in list {
        // Make sure we have the same amount of nonces and blinds
        assert_eq!(vector.blinds.len(), vector.nonces.len());

        let nr = vector.blinds.len();

        // Server: Instantiate in-memory keystore and nonce store.
        let key_store = MemoryKeyStoreVoprf::<CS>::default();
        let nonce_store = MemoryNonceStore::default();

        // Server: Create server
        let server = Server::<CS>::new();

        // Server: Create a new keypair
        let public_key = server.set_key(&key_store, &vector.sk_s).await.unwrap();

        // KAT: Check public key
        assert_eq!(serialize_public_key::<CS::Group>(public_key), vector.pk_s);

        // Convert parameters
        let token_challenge =
            TokenChallenge::deserialize(vector.token_challenge.as_slice()).unwrap();
        let challenge_digest: [u8; 32] = token_challenge.digest().unwrap();
        let nonces: Vec<[u8; 32]> = vector
            .nonces
            .iter()
            .map(|nonce| <[u8; 32]>::try_from(nonce.0.clone()).unwrap())
            .collect();
        let blinds = vector
            .blinds
            .iter()
            .map(|blind| <CS::Group as Group>::deserialize_scalar(&blind.0).unwrap())
            .collect();

        // KAT: Check token challenge type
        assert_eq!(token_challenge.token_type(), CS::token_type());

        // Client: Prepare a TokenRequest after having received a challenge
        let (token_request, token_state) = TokenRequest::issue_token_request_with_params(
            public_key,
            &token_challenge,
            nonces,
            blinds,
        )
        .unwrap();

        // KAT: Check token request
        assert_eq!(
            token_request.tls_serialize_detached().unwrap(),
            vector.token_request
        );

        // Server: Issue a TokenResponse
        let token_response = server
            .issue_token_response(&key_store, token_request)
            .await
            .unwrap();

        // KAT: Check token response
        let kat_token_response =
            TokenResponse::tls_deserialize(&mut vector.token_response.as_slice()).unwrap();

        assert_eq!(
            token_response.evaluated_elements(),
            kat_token_response.evaluated_elements()
        );

        // Client: Turn the TokenResponse into a Token
        let tokens = token_response.issue_tokens(&token_state).unwrap();

        // Server: Compare the challenge digest
        for (i, token) in tokens.iter().enumerate().take(nr) {
            assert_eq!(token.challenge_digest(), &challenge_digest);

            // Server: Redeem the token
            assert!(
                server
                    .redeem_token(&key_store, &nonce_store, token.clone())
                    .await
                    .is_ok()
            );

            // KAT: Check token
            assert_eq!(token.tls_serialize_detached().unwrap(), vector.tokens[i].0);
        }
    }
}

#[tokio::test]
async fn write_kat_batched_token() {
    write_kat_batched_token_type::<NistP384>("tests/kat_vectors/batched_p384_rs-new.json").await;
    write_kat_batched_token_type::<Ristretto255>(
        "tests/kat_vectors/batched_ristretto255_rs-new.json",
    )
    .await;
}

async fn write_kat_batched_token_type<CS: PPCipherSuite>(file: &str) {
    let mut elements = Vec::new();

    for _ in 0..5 {
        // Generate a new test vector
        let vector = generate_kat_batched_token::<CS>().await;

        elements.push(vector);
    }

    let data = serde_json::to_string_pretty(&elements).unwrap();

    evaluate_kat::<CS>(elements).await;

    let mut file = File::create(file).unwrap();
    file.write_all(data.as_bytes()).unwrap();
}

async fn generate_kat_batched_token<CS: PPCipherSuite>() -> BatchedTokenTestVector {
    let nr = 5u16;
    // Server: Instantiate in-memory keystore and nonce store.
    let key_store = MemoryKeyStoreVoprf::<CS>::default();
    let nonce_store = MemoryNonceStore::default();

    // Server: Create server
    let server = Server::new();

    // Server: Create a new keypair
    let mut seed = GenericArray::<_, <CS::Group as Group>::ScalarLen>::default();
    OsRng.fill_bytes(&mut seed);

    let info = b"PrivacyPass";

    let public_key = server
        .create_keypair_with_params(&key_store, &seed, info)
        .await
        .unwrap();

    let scalar = derive_key::<CS>(&seed, info, Mode::Voprf).unwrap();

    let sk_s = <CS::Group as Group>::serialize_scalar(scalar).to_vec();

    let pk_s = serialize_public_key::<CS::Group>(public_key);

    let redemption_context = if OsRng.next_u32() % 2 == 0 {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Some(bytes)
    } else {
        None
    };

    let kat_token_challenge = TokenChallenge::new(
        CS::token_type(),
        "Issuer Name",
        redemption_context,
        &["a".to_string(), "b".to_string(), "c".to_string()],
    );

    // Create a TokenChallenge
    let token_challenge = kat_token_challenge.tls_serialize_detached().unwrap();

    let challenge_digest: [u8; 32] = kat_token_challenge.digest().unwrap();

    let mut kat_nonces = Vec::with_capacity(nr as usize);

    for _ in 0..nr {
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        kat_nonces.push(nonce);
    }

    let nonces = kat_nonces
        .iter()
        .map(|nonce| HexNonce(nonce.clone().to_vec()))
        .collect();

    let kat_blinds = (0..nr)
        .map(|_| <CS::Group as Group>::random_scalar(&mut OsRng))
        .collect::<Vec<_>>();

    let blinds = kat_blinds
        .iter()
        .map(|blind| HexBlind(<CS::Group as Group>::serialize_scalar(*blind).to_vec()))
        .collect::<Vec<_>>();

    // Client: Prepare a TokenRequest after having received a challenge
    let (kat_token_request, token_states) = TokenRequest::issue_token_request_with_params(
        public_key,
        &kat_token_challenge,
        kat_nonces,
        kat_blinds,
    )
    .unwrap();

    let token_request = kat_token_request.tls_serialize_detached().unwrap();

    // Server: Issue a TokenResponse
    let kat_token_response = server
        .issue_token_response(&key_store, kat_token_request)
        .await
        .unwrap();

    let token_response = kat_token_response.tls_serialize_detached().unwrap();

    // Client: Turn the TokenResponse into a Token
    let kat_tokens = kat_token_response.issue_tokens(&token_states).unwrap();

    for token in kat_tokens.iter().take(nr as usize) {
        assert_eq!(token.challenge_digest(), &challenge_digest);

        // Server: Redeem the token
        assert!(
            server
                .redeem_token(&key_store, &nonce_store, token.clone())
                .await
                .is_ok()
        );
    }

    let tokens = kat_tokens
        .into_iter()
        .map(|token| HexToken(token.tls_serialize_detached().unwrap()))
        .collect::<Vec<_>>();

    BatchedTokenTestVector {
        sk_s,
        pk_s,
        token_challenge,
        nonces,
        blinds,
        token_request,
        token_response,
        tokens,
    }
}
