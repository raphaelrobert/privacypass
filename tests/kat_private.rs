mod private_memory_stores;

use std::num::ParseIntError;

use p384::NistP384;
use private_memory_stores::*;
use tls_codec::Serialize;
use voprf::Group;

use privacypass::{
    auth::authenticate::TokenChallenge,
    private_tokens::{client::*, server::*},
};

const SKS: &str = "08f572b675c83bf83c8037e503816119409a21d26e097414678eb44c625fcddd9b2e4eb16dbccc975c5ae745ffa3f4fa";
const PKS: &str = "0371b63695ddf79655f770ced74c17938d60c9cb9d8b9537614072b001ffc6085e80f310cdb4475487736f0f9d1406c7c9";
const CHALLENGE: &str = "0001000e6973737565722e6578616d706c6500000e6f726967696e2e6578616d706c65";
const NONCE: &str = "1a177bae66ea3341c367c160c635aa52daef9f105bb1240d06a063ae12e9798a";
const BLIND: &str = "1e46366a7b619aea7d7e24d2b853f5ddc64524eb5a78f4e3af108f02919827cbdea2f8d753869ab9229aeb7fe9988763";
const TOKEN_REQUEST: &str = "00017f023d788d4089a5f76f908ce26d18bb3b8ee826223b8a1df70a052e092aaf235c44c6f1e57f81d17d31632d090d260dc531";
const TOKEN_RESPONSE: &str = "03c1854b0cb631ceff11079299fdc5c8d9f94c6d7d6dbc862b259916a4dba69e39ac38817fafaa6e48842c610d41bf0bb6fa3ae6e3025acf2238c0ef02e0b628437944cdbd0207c86bd9c3025fcacbd0e520576c7ad9bb9cc1846687168e7c5226bdfd0c89be908d5d90eb60e5533045358e3063b6d3a24cc2f55891cded1a7642ef945bcec888e92e15d5ecdb431fdc6d";
const TOKEN: &str = "00011a177bae66ea3341c367c160c635aa52daef9f105bb1240d06a063ae12e9798ac994f7d5cdc2fb970b13d4e8eb6e6d8f9dcdaa65851fb091025dfe134bd5a62a7f13956db7526669425e8eb1128273c17972b5f16a9bc835a9c9f35772a2add9f5e1bb3ab71770ada81faf1af0fbdfa476fc92a3ff25fac14639b7fe34365118ae2ff55a2399e1580bec9aa759659317";

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
        token_response.tls_serialize_detached().unwrap(),
        expected_token_response
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
