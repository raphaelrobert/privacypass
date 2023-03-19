mod private_memory_stores;

use std::{fs::File, io::Write};

use generic_array::GenericArray;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

use p384::{elliptic_curve::Field, NistP384};
use private_memory_stores::*;
use tls_codec::Serialize as TlsSerializeTrait;
use voprf::{derive_key, Group, Mode};

use privacypass::{
    auth::authenticate::TokenChallenge,
    private_tokens::{client::*, server::*, NE},
};

#[derive(Serialize, Deserialize)]
struct PrivateTokenTestVector {
    #[serde(with = "hex", alias = "skS")]
    sk_s: Vec<u8>,
    #[serde(with = "hex", alias = "pkS")]
    pk_s: Vec<u8>,
    #[serde(with = "hex")]
    token_challenge: Vec<u8>,
    #[serde(with = "hex")]
    nonce: Vec<u8>,
    #[serde(with = "hex")]
    blind: Vec<u8>,
    #[serde(with = "hex")]
    token_request: Vec<u8>,
    #[serde(with = "hex")]
    token_response: Vec<u8>,
    #[serde(with = "hex")]
    token: Vec<u8>,
}

#[tokio::test]
async fn read_kat_private_token() {
    let list: Vec<PrivateTokenTestVector> =
        serde_json::from_str(include_str!("kat_vectors/private_vectors.json").trim()).unwrap();

    evaluate_kat(list).await;
}

async fn evaluate_kat(list: Vec<PrivateTokenTestVector>) {
    for (_, vector) in list.iter().enumerate() {
        // Server: Instantiate in-memory keystore and nonce store.
        let key_store = MemoryKeyStore::default();
        let nonce_store = MemoryNonceStore::default();

        // Server: Create server
        let mut server = Server::new();

        // Server: Create a new keypair
        let public_key = server.set_key(&key_store, &vector.sk_s).await.unwrap();

        // KAT: Check public key
        assert_eq!(serialize_public_key(public_key), vector.pk_s);

        // Client: Create client
        let mut client = Client::new(public_key);

        // Convert parameters
        let token_challenge =
            TokenChallenge::deserialize(vector.token_challenge.as_slice()).unwrap();
        let challenge_digest: [u8; 32] = token_challenge.digest().unwrap();
        let nonce: [u8; 32] = <[u8; 32]>::try_from(vector.nonce.as_ref()).unwrap();
        let blind = NistP384::deserialize_scalar(&vector.blind).unwrap();

        // Client: Prepare a TokenRequest after having received a challenge
        let (token_request, token_state) = client
            .issue_token_request_with_params(&token_challenge, nonce, blind)
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
        assert_eq!(
            token_response.tls_serialize_detached().unwrap()[..NE],
            vector.token_response[..NE]
        );

        // Client: Turn the TokenResponse into a Token
        let token = client.issue_token(&token_response, &token_state).unwrap();

        // Server: Compare the challenge digest
        assert_eq!(token.challenge_digest(), &challenge_digest);

        // Server: Redeem the token
        assert!(server
            .redeem_token(&key_store, &nonce_store, token.clone())
            .await
            .is_ok());

        // KAT: Check token
        assert_eq!(token.tls_serialize_detached().unwrap(), vector.token);
    }
}

#[tokio::test]
async fn write_kat_private_token() {
    let mut elements = Vec::new();

    for _ in 0..5 {
        // Server: Instantiate in-memory keystore and nonce store.
        let key_store = MemoryKeyStore::default();
        let nonce_store = MemoryNonceStore::default();

        // Server: Create server
        let mut server = Server::new();

        // Server: Create a new keypair
        let mut seed = GenericArray::<_, <NistP384 as Group>::ScalarLen>::default();
        OsRng.fill_bytes(&mut seed);

        let info = b"PrivacyPass";

        let public_key = server
            .create_keypair_with_params(&key_store, &seed, info)
            .await
            .unwrap();

        let sk_s = derive_key::<NistP384>(&seed, info, Mode::Voprf)
            .unwrap()
            .to_bytes()
            .to_vec();

        let pk_s = serialize_public_key(public_key);

        // Client: Create client
        let mut client = Client::new(public_key);

        let redemption_context = if OsRng.next_u32() % 2 == 0 {
            let mut bytes = [0u8; 32];
            OsRng.fill_bytes(&mut bytes);
            Some(bytes)
        } else {
            None
        };

        let kat_token_challenge = TokenChallenge::new(
            privacypass::TokenType::Private,
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

        let kat_blind = <NistP384 as Group>::Scalar::random(&mut OsRng);

        let blind = kat_blind.to_bytes().to_vec();

        // Client: Prepare a TokenRequest after having received a challenge
        let (kat_token_request, token_state) = client
            .issue_token_request_with_params(&kat_token_challenge, kat_nonce, kat_blind)
            .unwrap();

        let token_request = kat_token_request.tls_serialize_detached().unwrap();

        // Server: Issue a TokenResponse
        let kat_token_response = server
            .issue_token_response(&key_store, kat_token_request)
            .await
            .unwrap();

        let token_response = kat_token_response.tls_serialize_detached().unwrap();

        // Client: Turn the TokenResponse into a Token
        let kat_token = client
            .issue_token(&kat_token_response, &token_state)
            .unwrap();

        let token = kat_token.tls_serialize_detached().unwrap();

        // Server: Compare the challenge digest
        assert_eq!(kat_token.challenge_digest(), &challenge_digest);

        // Server: Redeem the token
        assert!(server
            .redeem_token(&key_store, &nonce_store, kat_token.clone())
            .await
            .is_ok());

        let vector = PrivateTokenTestVector {
            sk_s,
            pk_s,
            token_challenge,
            nonce,
            blind,
            token_request,
            token_response,
            token,
        };

        elements.push(vector);
    }

    let data = serde_json::to_string_pretty(&elements).unwrap();

    evaluate_kat(elements).await;

    let mut file = File::create("tests/kat_vectors/private_vectors_privacypass-new.json").unwrap();
    file.write_all(data.as_bytes()).unwrap();
}
