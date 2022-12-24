mod private_memory_stores;

use std::num::ParseIntError;

use p384::NistP384;
use private_memory_stores::*;
use tls_codec::Serialize;

use privacypass::private_tokens::{client::*, server::*};
use voprf::Group;

const SKS: &str = "0177781aeced893dccdf80713d318a801e2a0498240fdcf650304bbbfd0f8d3b5c0cf6cfee457aaa983ec02ff283b7a9";
const PKS: &str = "022c63f79ac59c0ba3d204245f676a2133bd6120c90d67afa05cd6f8614294b7366c252c6458300551b79a4911c2590a36";
const CHALLENGE: &str = "a5d46383359ef34e3c4a7b8d1b3165778bffc9b70c9e6a60dd14143e4c9c9fbd";
const NONCE: &str = "5d4799f8338ddc50a6685f83b8ecd264b2f157015229d12b3384c0f199efe7b8";
const BLIND: &str = "0322fec505230992256296063d989b59cc03e83184eb6187076d264137622d20248e4e525bdc007b80d1560e0a6f49d9";
const TOKEN_REQUEST: &str = "00011a02861fd50d14be873611cff0131d2c872c79d0260c6763498a2a3f14ca926009c0f247653406e1d52b68d61b7ed2bac9ea";
const TOKEN_RESPONSE: &str = "038e3625b6a769668a99680e46cf9479f5dc1e86d57164ab3b4a569ddfc486bf1485d4916a5194fdc0518d3e8444968421ba36e8144aa7902705ff0f3cf405863d69451a2a7ba210cc45760c2f1a6045134d877b39e8bcbbf920e5de4a3372557debf211765cd969976860bc039f9082d6a3e03f8e891246240173d2cf3d69a4613b0f8415979029";
const TOKEN: &str = "00015d4799f8338ddc50a6685f83b8ecd264b2f157015229d12b3384c0f199efe7b8742cdfb0ed756ea680868ef109a280a393e001d2fa56b1be46ecb31fa25e76731a5b1d698ea7ab843b8e8a71ed9b2fffa70457a43a8fc687939424b29a7554b40fde130ab7a822715909cb73f99a45b640ca1c85180ba9ca1a40bab8b664406a34bcbc63b5e2e5c455cea00001a968f7";

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
    let challenge_digest: [u8; 32] = challenge.try_into().unwrap();
    let nonce: [u8; 32] = nonce.try_into().unwrap();
    let blind = NistP384::deserialize_scalar(&blind).unwrap();

    // Client: Prepare a TokenRequest after having received a challenge
    let (token_request, token_state) = client
        .issue_token_request_with_params(challenge_digest, nonce, blind)
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
