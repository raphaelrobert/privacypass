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

const SKS: &str = "35fa7aec6cd717c64842a6cb856a735d699e83ad86c3262dd74fbf3f79c74826f8d1d19c69bb54fcdddb9565ccd7c0f8";
const PKS: &str = "037095ddd4a6c0e897b77a59fa825f2bcbeac985b32cd20ad16c4807791b2e41c4b5c567d0a4e7612a1909d86c9115f8f0";
const CHALLENGE: &str = "0001000e6973737565722e6578616d706c6500000e6f726967696e2e6578616d706c65";
const NONCE: &str = "72723e742f707f0187047374942245325926a8bd801389c1e6d9450a599d7272";
const BLIND: &str = "4d78b84e0eee597188987c11a36fa6ee5bdda7a1a009f1385a62ce69be152ad02280c66ecd44988728b4411fff3d8db3";

const TOKEN_REQUEST: &str = "0001240281823d29e743fbf6a7ef15f378e942ce2d6b3a4b67553ff2cd99877485dca7c0002630e1876d40ce1f2f872731d9375c";
const TOKEN_RESPONSE: &str = "030d6039bf857ffd4610f7f0f0a34146ad2dc72050751ec33483aef50bdfe275d56cd900bb6c7550224916ffbd32ddeb21c6e47d14535430f7ece5efd00ad34c33dd5d637ed80a3607ad64495f12afdff12c72a4e4f79b8502b05c2bd5a78394b531f400db6d5c32fb26c1a0966d606c64c9200fc0cc32864715a0b78dcbfda5a2f74000c98b9b23a7eb055da4a7f03bc7";
const TOKEN: &str = "000172723e742f707f0187047374942245325926a8bd801389c1e6d9450a599d7272c994f7d5cdc2fb970b13d4e8eb6e6d8f9dcdaa65851fb091025dfe134bd5a62ac00097624086fc5741ae2ea023164c0ed16259813a04da1b2f6bf38983d817240a5f1995837c9b209a13c3938085de952f074707d8e7132fe75a615d5072dcebde1f74c435211eca4315202607fd0761";

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
