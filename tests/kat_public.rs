use std::{fs::File, io::Write};

use serde::{Deserialize, Serialize};

use blind_rsa_signatures::{KeyPair, Options, PublicKey, SecretKey};

use rand::{RngCore, rngs::OsRng};
use tls_codec::Serialize as TlsSerializeTrait;

use privacypass::{
    Nonce,
    auth::authenticate::TokenChallenge,
    public_tokens::{
        TokenRequest, det_rng::DeterministicRng, public_key_to_truncated_token_key_id, server::*,
    },
    test_utils::{
        nonce_store::MemoryNonceStore,
        public_memory_store::{IssuerMemoryKeyStore, OriginMemoryKeyStore},
    },
};

#[derive(Serialize, Deserialize)]
pub(crate) struct PublicTokenTestVector {
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
    pub(crate) salt: Vec<u8>,
    #[serde(with = "hex")]
    pub(crate) token_request: Vec<u8>,
    #[serde(with = "hex")]
    pub(crate) token_response: Vec<u8>,
    #[serde(with = "hex")]
    pub(crate) token: Vec<u8>,
}

#[tokio::test]
async fn read_kat_public_token() {
    // === Check own KAT vectors ===

    let list: Vec<PublicTokenTestVector> =
        serde_json::from_str(include_str!("kat_vectors/public_rs.json").trim()).unwrap();
    evaluate_kat(list).await;

    // === Check KAT vectors from Go ===

    let list: Vec<PublicTokenTestVector> =
        serde_json::from_str(include_str!("kat_vectors/public_go.json").trim()).unwrap();
    evaluate_kat(list).await;
}

async fn evaluate_kat(list: Vec<PublicTokenTestVector>) {
    for vector in list {
        evaluate_vector(vector).await;
    }
}

pub(crate) async fn evaluate_vector(vector: PublicTokenTestVector) {
    // Server: Instantiate in-memory keystore and nonce store.
    let issuer_key_store = IssuerMemoryKeyStore::default();
    let origin_key_store = OriginMemoryKeyStore::default();
    let nonce_store = MemoryNonceStore::default();

    // Server: Create servers for issuer and origin
    let issuer_server = IssuerServer::new();
    let origin_server = OriginServer::new();

    // Keys
    let options = Options::default();

    let sec_key = SecretKey::from_pem(&String::from_utf8_lossy(&vector.sk_s)).unwrap();
    let pub_key = PublicKey::from_spki(&vector.pk_s, Some(&options)).unwrap();

    // KAT: Check public key
    // Derive the public key from the private and compare it
    assert_eq!(sec_key.to_public_key(), pub_key.0);

    // Serialize the public key and compare it
    assert_eq!(serialize_public_key(&pub_key), vector.pk_s);

    let keypair = KeyPair {
        sk: sec_key,
        pk: pub_key.clone(),
    };

    // Issuer server: Set the keypair
    issuer_server.set_keypair(&issuer_key_store, keypair).await;

    // Origin key store: Set the public key
    origin_key_store
        .insert(
            public_key_to_truncated_token_key_id(&pub_key),
            pub_key.clone(),
        )
        .await;

    // Prepare the deterministic number generator
    let mut blind = vector.blind.clone();
    blind.reverse();

    let det_rng = &mut DeterministicRng::new(vector.nonce.clone(), vector.salt.clone(), blind);

    let token_challenge = TokenChallenge::deserialize(vector.token_challenge.as_slice()).unwrap();
    let challenge_digest: [u8; 32] = token_challenge.digest().unwrap();

    // KAT: Check token challenge type
    assert_eq!(token_challenge.token_type(), privacypass::TokenType::Public);

    let (token_request, token_state) =
        TokenRequest::new(det_rng, pub_key, &token_challenge).unwrap();

    // KAT: Check token request
    assert_eq!(
        token_request.tls_serialize_detached().unwrap(),
        vector.token_request
    );

    // Issuer server: Issue a TokenResponse
    let token_response = issuer_server
        .issue_token_response(&issuer_key_store, token_request)
        .await
        .unwrap();

    // KAT: Check token response
    assert_eq!(
        token_response.tls_serialize_detached().unwrap(),
        vector.token_response
    );

    // Client: Turn the TokenResponse into a Token
    let token = token_response.issue_token(&token_state).unwrap();

    // Compare the challenge digest
    assert_eq!(token.challenge_digest(), &challenge_digest);

    // Origin server: Redeem the token
    assert!(
        origin_server
            .redeem_token(&origin_key_store, &nonce_store, token.clone())
            .await
            .is_ok()
    );

    // KAT: Check token
    assert_eq!(token.tls_serialize_detached().unwrap(), vector.token);
}

#[tokio::test]
async fn write_kat_public_token() {
    let mut elements = Vec::new();

    for _ in 0..5 {
        // Generate a new test vector
        let vector = generate_kat_public_token().await;

        elements.push(vector);
    }

    let data = serde_json::to_string_pretty(&elements).unwrap();

    evaluate_kat(elements).await;

    let mut file = File::create("tests/kat_vectors/public_rs-new.json").unwrap();
    file.write_all(data.as_bytes()).unwrap();
}

pub(crate) async fn generate_kat_public_token() -> PublicTokenTestVector {
    // Server: Instantiate in-memory keystore and nonce store.
    let issuer_key_store = IssuerMemoryKeyStore::default();
    let origin_key_store = OriginMemoryKeyStore::default();
    let nonce_store = MemoryNonceStore::default();

    // Server: Create servers for issuer and origin
    let issuer_server = IssuerServer::new();
    let origin_server = OriginServer::new();

    // Keys
    let keypair = KeyPair::generate(&mut OsRng, 2048).unwrap();

    let sk_s = keypair.sk.to_pem().unwrap().into_bytes();
    let pk_s = serialize_public_key(&keypair.pk);

    // Issuer server: Set the keypair
    issuer_server
        .set_keypair(&issuer_key_store, keypair.clone())
        .await;

    // Origin key store: Set the public key
    origin_key_store
        .insert(
            public_key_to_truncated_token_key_id(&keypair.pk),
            keypair.pk.clone(),
        )
        .await;

    // Prepare the deterministic number generator
    let mut nonce: Nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);

    let mut blind = [0u8; 256];
    OsRng.fill_bytes(&mut blind);

    let mut salt = [0u8; 48];
    OsRng.fill_bytes(&mut salt);

    let det_rng = &mut DeterministicRng::new(
        nonce.clone().to_vec(),
        salt.clone().to_vec(),
        blind.clone().to_vec(),
    );

    let redemption_context = if OsRng.next_u32() % 2 == 0 {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Some(bytes)
    } else {
        None
    };

    let kat_token_challenge = TokenChallenge::new(
        privacypass::TokenType::Public,
        "Issuer Name",
        redemption_context,
        &["a".to_string(), "b".to_string(), "c".to_string()],
    );

    let token_challenge = kat_token_challenge.tls_serialize_detached().unwrap();

    let challenge_digest: [u8; 32] = kat_token_challenge.digest().unwrap();

    let (kat_token_request, token_state) =
        TokenRequest::new(det_rng, keypair.pk, &kat_token_challenge).unwrap();

    let nonce = nonce.to_vec();
    let mut blind = blind.to_vec();
    let salt = salt.to_vec();

    if let Some(additional_blind) = det_rng.additional_blind() {
        blind = additional_blind.to_vec();
    }

    blind.reverse();

    let token_request = kat_token_request.tls_serialize_detached().unwrap();

    // Issuer server: Issue a TokenResponse
    let kat_token_response = issuer_server
        .issue_token_response(&issuer_key_store, kat_token_request)
        .await
        .unwrap();

    let token_response = kat_token_response.tls_serialize_detached().unwrap();

    // Client: Turn the TokenResponse into a Token
    let kat_token = kat_token_response.issue_token(&token_state).unwrap();

    let token = kat_token.tls_serialize_detached().unwrap();

    // Compare the challenge digest
    assert_eq!(kat_token.challenge_digest(), &challenge_digest);

    // Origin server: Redeem the token
    assert!(
        origin_server
            .redeem_token(&origin_key_store, &nonce_store, kat_token.clone())
            .await
            .is_ok()
    );

    PublicTokenTestVector {
        sk_s,
        pk_s,
        token_challenge,
        nonce,
        blind,
        salt,
        token_request,
        token_response,
        token,
    }
}
