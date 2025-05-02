use std::{fs::File, io::Write};

use generic_array::GenericArray;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};

use p384::NistP384;
use tls_codec::{Deserialize as _, Serialize as TlsSerializeTrait};
use voprf::{Group, Mode, Ristretto255, derive_key};

use privacypass::{
    PPCipherSuite,
    auth::authenticate::TokenChallenge,
    common::private::serialize_public_key,
    private_tokens::{TokenRequest, TokenResponse, server::*},
    test_utils::{nonce_store::MemoryNonceStore, private_memory_store::MemoryKeyStoreVoprf},
};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PrivateTokenTestVector {
    #[serde(with = "hex", alias = "skS")]
    pub(crate) sk_s: Vec<u8>,
    #[serde(with = "hex", alias = "pkS")]
    pub(crate) pk_s: Vec<u8>,
    #[serde(with = "hex")]
    pub(crate) token_challenge: Vec<u8>,
    #[serde(with = "hex")]
    pub(crate) nonce: Vec<u8>,
    #[serde(with = "hex")]
    pub(crate) blind: Vec<u8>,
    #[serde(with = "hex")]
    pub(crate) token_request: Vec<u8>,
    #[serde(with = "hex")]
    pub(crate) token_response: Vec<u8>,
    #[serde(with = "hex")]
    pub(crate) token: Vec<u8>,
}

#[tokio::test]
async fn read_kat_private_token() {
    // === Check own KAT vectors ===

    // P384
    let list: Vec<PrivateTokenTestVector> =
        serde_json::from_str(include_str!("kat_vectors/private_p384_rs.json").trim()).unwrap();
    evaluate_kat::<NistP384>(list).await;

    // Ristretto255
    let list: Vec<PrivateTokenTestVector> =
        serde_json::from_str(include_str!("kat_vectors/private_ristretto_rs.json").trim()).unwrap();
    evaluate_kat::<Ristretto255>(list).await;

    // === Check KAT vectors from Go ===
    // TODO: Add Go KAT vectors
}

async fn evaluate_kat<CS: PPCipherSuite>(list: Vec<PrivateTokenTestVector>) {
    for vector in list {
        evaluate_vector::<CS>(vector).await;
    }
}

pub(crate) async fn evaluate_vector<CS: PPCipherSuite>(vector: PrivateTokenTestVector) {
    // Server: Instantiate in-memory keystore and nonce store.
    let key_store = MemoryKeyStoreVoprf::<CS>::default();
    let nonce_store = MemoryNonceStore::default();

    // Server: Create server
    let server = Server::new();

    // Server: Create a new keypair
    let public_key = server.set_key(&key_store, &vector.sk_s).await.unwrap();

    // KAT: Check public key
    assert_eq!(serialize_public_key::<CS::Group>(public_key), vector.pk_s);

    // Convert parameters
    let token_challenge = TokenChallenge::deserialize(vector.token_challenge.as_slice()).unwrap();
    let challenge_digest: [u8; 32] = token_challenge.digest().unwrap();
    let nonce: [u8; 32] = <[u8; 32]>::try_from(vector.nonce.as_ref()).unwrap();
    let blind = <CS::Group as Group>::deserialize_scalar(&vector.blind).unwrap();

    // Client: Prepare a TokenRequest after having received a challenge
    let (token_request, token_state) =
        TokenRequest::issue_token_request_with_params(public_key, &token_challenge, nonce, blind)
            .unwrap();

    // KAT: Check token challenge type
    assert_eq!(token_challenge.token_type(), CS::token_type());

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
        TokenResponse::<CS>::tls_deserialize(&mut vector.token_response.as_slice()).unwrap();

    assert_eq!(
        token_response.evaluate_msg(),
        kat_token_response.evaluate_msg()
    );

    // Client: Turn the TokenResponse into a Token
    let token = token_response.issue_token(&token_state).unwrap();

    // Server: Compare the challenge digest
    assert_eq!(token.challenge_digest(), &challenge_digest);

    // Server: Redeem the token
    assert!(
        server
            .redeem_token(&key_store, &nonce_store, token.clone())
            .await
            .is_ok()
    );

    // KAT: Check token
    assert_eq!(token.tls_serialize_detached().unwrap(), vector.token);
}

#[tokio::test]
async fn write_kat_private_token() {
    write_kat_private_token_type::<NistP384>("tests/kat_vectors/private_p384_rs-new.json").await;
    write_kat_private_token_type::<Ristretto255>("tests/kat_vectors/private_ristretto_rs-new.json")
        .await;
}

async fn write_kat_private_token_type<CS: PPCipherSuite>(file: &str) {
    let mut elements = Vec::new();

    for _ in 0..5 {
        // Generate a new test vector
        let vector = generate_kat_private_token::<CS>().await;

        elements.push(vector);
    }

    let data = serde_json::to_string_pretty(&elements).unwrap();

    evaluate_kat::<CS>(elements).await;

    let mut file = File::create(file).unwrap();
    file.write_all(data.as_bytes()).unwrap();
}

pub(crate) async fn generate_kat_private_token<CS: PPCipherSuite>() -> PrivateTokenTestVector {
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

    let mut kat_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut kat_nonce);
    let nonce = kat_nonce.to_vec();

    let kat_blind = <CS::Group as Group>::random_scalar(&mut OsRng);

    let blind = <CS::Group as Group>::serialize_scalar(kat_blind).to_vec();

    // Client: Prepare a TokenRequest after having received a challenge
    let (kat_token_request, token_state) = TokenRequest::<CS>::issue_token_request_with_params(
        public_key,
        &kat_token_challenge,
        kat_nonce,
        kat_blind,
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
    let kat_token = kat_token_response.issue_token(&token_state).unwrap();

    let token = kat_token.tls_serialize_detached().unwrap();

    // Server: Compare the challenge digest
    assert_eq!(kat_token.challenge_digest(), &challenge_digest);

    // Server: Redeem the token
    assert!(
        server
            .redeem_token(&key_store, &nonce_store, kat_token.clone())
            .await
            .is_ok()
    );

    PrivateTokenTestVector {
        sk_s,
        pk_s,
        token_challenge,
        nonce,
        blind,
        token_request,
        token_response,
        token,
    }
}
