mod private_memory_stores;

use std::num::ParseIntError;

use p384::NistP384;
use private_memory_stores::*;
use tls_codec::Serialize;
use voprf::Group;

use privacypass::{
    auth::authenticate::TokenChallenge,
    private_tokens::{client::*, server::*, NE},
};

const SKS: &str = "3897b393bca7393f3373972472427655474e7110e7792ecc07212363644f0cbacecb31d34b7d913a1aa8bb7628fd3400";
const PKS: &str = "034a1a030a25546ce56fe40f0d7dcdfcbdfd56e83affe3e3b2953a0e940111298c13a9b87520e003b63affc7957f747d60";
const CHALLENGE: &str = "0001000e6973737565722e6578616d706c6500000e6f726967696e2e6578616d706c65";
const NONCE: &str = "e8be1d043af17dd9f2a6fe3771c39ea098628428fc202c00e15066cf2fb3237e";
const BLIND: &str = "50af9570a6ccf4ece5cd43296a08056681eda548e37d55db1a2537ad95ac5795f5e9787bc1aa1332c16970d3388a4c0f";
const TOKEN_REQUEST: &str = "0001d002f40eeccab27cce578be549b2c12c275d2102812358d059b711f112f726f6f2da13aaa071a536e87be865634c9bc1497c";
const TOKEN_RESPONSE: &str = "027b023b35d28bd2b037c0449a2835bac1b76e38359e89493ac592fee50fcbbe7b9277d243f3aa2b3c36bbe69838668364f1056df48d5dd0563e163e9368ce8fb1640cb3ff2df7ab88f8a669ef37cce3afc0937f7052e78b35ef9a76ce6ae6f67921446bc07b478e886622711aa53eb7a91034b78a5d957fc956aaba541c86f034872894666330b7dce5539074a728b485";
const TOKEN: &str = "0001e8be1d043af17dd9f2a6fe3771c39ea098628428fc202c00e15066cf2fb3237ec994f7d5cdc2fb970b13d4e8eb6e6d8f9dcdaa65851fb091025dfe134bd5a62ad0adb6d31efe8cf6f965b60a1beb66138597ade0572223a4c6dc005a8ff01fdd24b734c2abcf8a995343d28ff3fcae12e664faf55dfbe969ef1f834571276964d0f25df7c1a7edc1bde01b794eb35193";

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

#[tokio::test]
async fn kat_private_token() {
    // KAT: Decode hex strings
    let sks = decode_hex(SKS).unwrap();
    let pks = decode_hex(PKS).unwrap();
    let challenge = decode_hex(CHALLENGE).unwrap();
    let nonce = decode_hex(NONCE).unwrap();
    let blind = decode_hex(BLIND).unwrap();
    let expected_token_request = decode_hex(TOKEN_REQUEST).unwrap();
    let expected_token_response = decode_hex(TOKEN_RESPONSE).unwrap();
    let expected_token = decode_hex(TOKEN).unwrap();

    // Server: Instantiate in-memory keystore and nonce store.
    let key_store = MemoryKeyStore::default();
    let nonce_store = MemoryNonceStore::default();

    // Server: Create server
    let mut server = Server::new();

    // Server: Create a new keypair
    let public_key = server.set_key(&key_store, &sks).await.unwrap();

    // KAT: Check public key
    assert_eq!(serialize_public_key(public_key), pks);

    // Client: Create client
    let mut client = Client::new(public_key);

    // Convert parameters
    let token_challenge = TokenChallenge::deserialize(challenge.as_slice()).unwrap();
    let challenge_digest: [u8; 32] = token_challenge.digest().unwrap();
    let nonce: [u8; 32] = nonce.try_into().unwrap();
    let blind = NistP384::deserialize_scalar(&blind).unwrap();

    // Client: Prepare a TokenRequest after having received a challenge
    let (token_request, token_state) = client
        .issue_token_request_with_params(&token_challenge, nonce, blind)
        .unwrap();

    // KAT: Check token request
    assert_eq!(
        token_request.tls_serialize_detached().unwrap(),
        expected_token_request
    );

    // Server: Issue a TokenResponse
    let token_response = server
        .issue_token_response(&key_store, token_request)
        .await
        .unwrap();

    // KAT: Check token response
    assert_eq!(
        token_response.tls_serialize_detached().unwrap()[..NE],
        expected_token_response[..NE]
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
    assert_eq!(token.tls_serialize_detached().unwrap(), expected_token);
}
