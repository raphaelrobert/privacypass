mod public_memory_stores;

use serde::Deserialize;

use std::num::ParseIntError;

use blind_rsa_signatures::{KeyPair, Options, PublicKey, SecretKey};

use public_memory_stores::*;
use rand::{CryptoRng, Error, RngCore};
use tls_codec::Serialize;

use privacypass::{
    auth::authenticate::TokenChallenge,
    public_tokens::{client::*, public_key_to_token_key_id, server::*},
};

#[derive(Deserialize)]
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
async fn kat_public_token() {
    let list: Vec<PublicTokenTestVector> =
        serde_json::from_str(include_str!("public_vectors.json").trim()).unwrap();
    for (_, vector) in list.iter().enumerate() {
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

// Helper RNG that returns the same set of values for each call to (try_)fill_bytes.

enum RngStep {
    Nonce,
    Blind,
    Salt,
}

struct DeterministicRng {
    nonce: Vec<u8>,
    salt: Vec<u8>,
    blind: Vec<u8>,
    step: RngStep,
}

impl DeterministicRng {
    #[cfg(test)]
    fn new(nonce: Vec<u8>, salt: Vec<u8>, blind: Vec<u8>) -> Self {
        Self {
            nonce,
            salt,
            blind,
            step: RngStep::Nonce,
        }
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
                self.step = RngStep::Nonce;
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
