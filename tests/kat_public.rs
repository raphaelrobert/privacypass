mod public_memory_stores;

use std::{fs::File, io::Write};

use serde::{Deserialize, Serialize};

use blind_rsa_signatures::{KeyPair, Options, PublicKey, SecretKey};

use public_memory_stores::*;
use rand::{rngs::OsRng, CryptoRng, Error, RngCore};
use tls_codec::Serialize as TlsSerializeTrait;

use privacypass::{
    auth::authenticate::TokenChallenge,
    public_tokens::{client::*, public_key_to_token_key_id, server::*},
    Nonce,
};

#[derive(Serialize, Deserialize)]
struct PublicTokenTestVector {
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
    salt: Vec<u8>,
    #[serde(with = "hex")]
    token_request: Vec<u8>,
    #[serde(with = "hex")]
    token_response: Vec<u8>,
    #[serde(with = "hex")]
    token: Vec<u8>,
}

#[tokio::test]
async fn read_kat_public_token() {
    let list: Vec<PublicTokenTestVector> =
        serde_json::from_str(include_str!("kat_vectors/public_vectors.json").trim()).unwrap();

    evaluate_kat(list).await;
}

async fn evaluate_kat(list: Vec<PublicTokenTestVector>) {
    for vector in list {
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
            .insert(public_key_to_token_key_id(&pub_key), pub_key.clone())
            .await;

        // Client: Create client
        let mut client = Client::new(pub_key);

        // Prepare the deterministic number generator
        let mut blind = vector.blind.clone();
        blind.reverse();

        let det_rng = &mut DeterministicRng::new(vector.nonce.clone(), vector.salt.clone(), blind);

        let token_challenge =
            TokenChallenge::deserialize(vector.token_challenge.as_slice()).unwrap();
        let challenge_digest: [u8; 32] = token_challenge.digest().unwrap();

        let (token_request, token_state) = client
            .issue_token_request(det_rng, token_challenge)
            .unwrap();

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
        let token = client.issue_token(token_response, &token_state).unwrap();

        // Compare the challenge digest
        assert_eq!(token.challenge_digest(), &challenge_digest);

        // Origin server: Redeem the token
        assert!(origin_server
            .redeem_token(&origin_key_store, &nonce_store, token.clone())
            .await
            .is_ok());

        // KAT: Check token
        assert_eq!(token.tls_serialize_detached().unwrap(), vector.token);
    }
}

#[tokio::test]
async fn write_kat_public_token() {
    let mut elements = Vec::new();

    for _ in 0..5 {
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
            .insert(public_key_to_token_key_id(&keypair.pk), keypair.pk.clone())
            .await;

        // Client: Create client
        let mut client = Client::new(keypair.pk);

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
            privacypass::TokenType::PublicToken,
            "Issuer Name",
            redemption_context,
            &["a".to_string(), "b".to_string(), "c".to_string()],
        );

        let token_challenge = kat_token_challenge.tls_serialize_detached().unwrap();

        let challenge_digest: [u8; 32] = kat_token_challenge.digest().unwrap();

        let (kat_token_request, token_state) = client
            .issue_token_request(det_rng, kat_token_challenge)
            .unwrap();

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
        let kat_token = client
            .issue_token(kat_token_response, &token_state)
            .unwrap();

        let token = kat_token.tls_serialize_detached().unwrap();

        // Compare the challenge digest
        assert_eq!(kat_token.challenge_digest(), &challenge_digest);

        // Origin server: Redeem the token
        assert!(origin_server
            .redeem_token(&origin_key_store, &nonce_store, kat_token.clone())
            .await
            .is_ok());

        let vector = PublicTokenTestVector {
            sk_s,
            pk_s,
            token_challenge,
            nonce,
            blind,
            salt,
            token_request,
            token_response,
            token,
        };

        elements.push(vector);
    }

    let data = serde_json::to_string_pretty(&elements).unwrap();

    evaluate_kat(elements).await;

    let mut file = File::create("tests/kat_vectors/public_vectors_privacypass-new.json").unwrap();
    file.write_all(data.as_bytes()).unwrap();
}

// Helper RNG that returns the same set of values for each call to (try_)fill_bytes.

enum RngStep {
    Nonce,
    Salt,
    Blind,
    AdditionalBlind,
}

struct DeterministicRng {
    nonce: Vec<u8>,
    salt: Vec<u8>,
    blind: Vec<u8>,
    additional_blind: Option<Vec<u8>>,
    step: RngStep,
}

impl DeterministicRng {
    fn new(nonce: Vec<u8>, salt: Vec<u8>, blind: Vec<u8>) -> Self {
        Self {
            nonce,
            salt,
            blind,
            additional_blind: None,
            step: RngStep::Nonce,
        }
    }

    fn additional_blind(&self) -> Option<&[u8]> {
        self.additional_blind.as_deref()
    }

    fn fill_with_data(&mut self, dest: &mut [u8]) {
        match self.step {
            RngStep::Nonce => {
                dest.copy_from_slice(&self.nonce);
                self.step = RngStep::Salt;
            }
            RngStep::Salt => {
                dest.copy_from_slice(&self.salt);
                self.step = RngStep::Blind;
            }
            RngStep::Blind => {
                dest.copy_from_slice(&self.blind);
                self.step = RngStep::AdditionalBlind;
            }
            RngStep::AdditionalBlind => {
                let mut ab = [0u8; 256];
                OsRng.fill_bytes(&mut ab);
                dest.copy_from_slice(&ab);
                self.additional_blind = Some(ab.to_vec());
                self.step = RngStep::AdditionalBlind;
            }
        }
    }
}

impl RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }

    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.fill_with_data(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_with_data(dest);
        Ok(())
    }
}

impl CryptoRng for DeterministicRng {}
