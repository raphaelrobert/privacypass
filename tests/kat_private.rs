mod private_memory_stores;

use serde::Deserialize;

use p384::NistP384;
use private_memory_stores::*;
use tls_codec::Serialize;
use voprf::Group;

use privacypass::{
    auth::authenticate::TokenChallenge,
    private_tokens::{client::*, server::*, NE},
};

#[derive(Deserialize)]
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
        serde_json::from_str(include_str!("private_vectors.json").trim()).unwrap();
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
