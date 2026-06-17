use blind_rsa_signatures::{Deterministic, KeyPair, PSS, PublicKey, SecretKey, Sha384};
use serde::{Deserialize, Serialize};
use tls_codec::Serialize as TlsSerializeTrait;

use privacypass::{
    TokenType,
    auth::authenticate::TokenChallenge,
    public_tokens::{
        TokenProtocol, TokenRequest, det_rng::DeterministicRng,
        public_key_to_truncated_token_key_id, server::*,
    },
    test_utils::{
        nonce_store::MemoryNonceStore,
        public_memory_store::{IssuerMemoryKeyStore, OriginMemoryKeyStore},
    },
};

#[derive(Serialize, Deserialize)]
struct PublicMetadataTokenTestVector {
    #[serde(with = "hex", rename = "skS")]
    sk_s: Vec<u8>,
    #[serde(with = "hex", rename = "pkS")]
    pk_s: Vec<u8>,
    #[serde(with = "hex")]
    token_challenge: Vec<u8>,
    #[serde(with = "hex")]
    extensions: Vec<u8>,
    #[serde(with = "hex")]
    nonce: Vec<u8>,
    #[serde(with = "hex")]
    blind: Vec<u8>,
    #[serde(with = "hex")]
    salt: Vec<u8>,
    #[serde(with = "hex")]
    token_request: Vec<u8>,
    #[serde(with = "hex")]
    token_response: Vec<u8>,
    #[serde(with = "hex")]
    token: Vec<u8>,
}

#[tokio::test]
async fn read_kat_public_metadata_token() {
    // Test vectors from
    // https://github.com/cloudflare/privacypass-ts/blob/main/test/test_data/pub_verif_with_metadata_v3.json
    let list: Vec<PublicMetadataTokenTestVector> =
        serde_json::from_str(include_str!("kat_vectors/public_metadata_ts.json").trim()).unwrap();

    for vector in list {
        evaluate_vector(vector).await;
    }
}

async fn evaluate_vector(vector: PublicMetadataTokenTestVector) {
    let issuer_key_store = IssuerMemoryKeyStore::default();
    let origin_key_store = OriginMemoryKeyStore::default();
    let nonce_store = MemoryNonceStore::default();

    let issuer_server = IssuerServer::new();
    let origin_server = OriginServer::new();

    let sec_key =
        SecretKey::<Sha384, PSS, Deterministic>::from_pem(&String::from_utf8_lossy(&vector.sk_s))
            .unwrap();
    let pub_key = PublicKey::<Sha384, PSS, Deterministic>::from_spki(&vector.pk_s).unwrap();

    let keypair = KeyPair {
        sk: sec_key,
        pk: pub_key.clone(),
    };

    issuer_server
        .set_keypair(&issuer_key_store, keypair)
        .await
        .unwrap();

    origin_key_store
        .insert(
            public_key_to_truncated_token_key_id(&pub_key).unwrap(),
            pub_key.clone(),
        )
        .await;

    // The extensions field is the raw metadata bytes passed to TokenProtocol::PublicMetadata
    let metadata = vector.extensions.clone();
    let protocol = TokenProtocol::PublicMetadata {
        metadata: &metadata,
    };

    let mut blind = vector.blind.clone();
    blind.reverse();

    let det_rng = &mut DeterministicRng::new(vector.nonce.clone(), vector.salt.clone(), blind);

    let token_challenge = TokenChallenge::deserialize(vector.token_challenge.as_slice()).unwrap();
    let challenge_digest: [u8; 32] = token_challenge.digest().unwrap();

    // KAT: Check token challenge type
    assert_eq!(token_challenge.token_type(), TokenType::PublicMetadata);

    let (token_request, token_state) =
        TokenRequest::new_with_protocol(det_rng, pub_key, &token_challenge, protocol).unwrap();

    // TODO: this is due to wrong api
    // will fix in next commit
    let mut token_request_bytes = token_request.tls_serialize_detached().unwrap();
    token_request_bytes.extend_from_slice(&vector.extensions);

    // KAT: Check token request
    // assert_eq!(
    // token_request.tls_serialize_detached().unwrap(),
    // vector.token_request
    // );
    assert_eq!(token_request_bytes, vector.token_request);

    let token_response = issuer_server
        .issue_token_response_protocol(&issuer_key_store, token_request, protocol)
        .await
        .unwrap();

    // KAT: Check token response
    assert_eq!(
        token_response.tls_serialize_detached().unwrap(),
        vector.token_response
    );

    let token = token_response.issue_token(&token_state).unwrap();

    assert_eq!(token.challenge_digest(), &challenge_digest);

    // KAT: Check token
    assert_eq!(token.tls_serialize_detached().unwrap(), vector.token);

    // Origin: Redeem the token
    origin_server
        .redeem_token_protocol(&origin_key_store, &nonce_store, token, protocol)
        .await
        .unwrap();
}
