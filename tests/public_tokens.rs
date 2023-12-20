mod public_memory_stores;

use public_memory_stores::*;

use blind_rsa_signatures::reexports::rsa::RsaPrivateKey;
use blind_rsa_signatures::{KeyPair, PublicKey, SecretKey};
use num_bigint_dig::BigUint;
use privacypass::{
    auth::authenticate::TokenChallenge,
    public_tokens::{client::*, public_key_to_token_key_id, server::*, TokenProtocol},
    KeyId, TokenType,
};
use rand::thread_rng;
use sha2::{Digest, Sha256};

#[tokio::test]
async fn public_tokens_cycle() {
    let rng = &mut thread_rng();

    // Server: Instantiate in-memory keystore and nonce store.
    let issuer_key_store = IssuerMemoryKeyStore::default();
    let origin_key_store = OriginMemoryKeyStore::default();
    let nonce_store = MemoryNonceStore::default();

    // Server: Create servers for issuer and origin
    let issuer_server = IssuerServer::new();
    let origin_server = OriginServer::new();

    // Issuer server: Create a new keypair
    let key_pair = issuer_server
        .create_keypair(&mut rand::thread_rng(), &issuer_key_store)
        .await
        .unwrap();

    let public_key = key_pair.pk;

    origin_key_store
        .insert(public_key_to_token_key_id(&public_key), public_key.clone())
        .await;

    // Client: Create client
    let mut client = Client::new(public_key);

    // Generate a challenge
    let token_challenge = TokenChallenge::new(
        TokenType::Public,
        "example.com",
        None,
        &["example.com".to_string()],
    );
    let challenge_digest = token_challenge.digest().unwrap();

    // Client: Prepare a TokenRequest after having received a challenge
    let (token_request, token_state) = client.issue_token_request(rng, token_challenge).unwrap();

    // Issuer server: Issue a TokenResponse
    let token_response = issuer_server
        .issue_token_response(&issuer_key_store, token_request)
        .await
        .unwrap();

    // Client: Turn the TokenResponse into a Token
    let token = client.issue_token(token_response, &token_state).unwrap();

    // Origin server: Compare the challenge digest
    assert_eq!(token.challenge_digest(), &challenge_digest);

    // Origin server: Redeem the token
    assert!(origin_server
        .redeem_token(&origin_key_store, &nonce_store, token.clone())
        .await
        .is_ok());

    // Origin server: Test double spend protection
    assert_eq!(
        origin_server
            .redeem_token(&origin_key_store, &nonce_store, token)
            .await,
        Err(RedeemTokenError::DoubleSpending)
    );
}

fn hex_to_biguint(h: &[u8]) -> BigUint {
    BigUint::from_bytes_be(
        &h.chunks(2)
            .map(|x| u8::from_str_radix(std::str::from_utf8(x).unwrap(), 16).unwrap())
            .collect::<Vec<_>>(),
    )
}

#[tokio::test]
async fn public_metadata_tokens() {
    // https://gist.github.com/chris-wood/b77536febb25a5a11af428afff77820a
    const P_ENC: &[u8] = b"dcd90af1be463632c0d5ea555256a20605af3db667475e190e3af12a34a3324c46a3094062c59fb4b249e0ee6afba8bee14e0276d126c99f4784b23009bf6168ff628ac1486e5ae8e23ce4d362889de4df63109cbd90ef93db5ae64372bfe1c55f832766f21e94ea3322eb2182f10a891546536ba907ad74b8d72469bea396f3";
    const Q_ENC: &[u8] = b"f8ba5c89bd068f57234a3cf54a1c89d5b4cd0194f2633ca7c60b91a795a56fa8c8686c0e37b1c4498b851e3420d08bea29f71d195cfbd3671c6ddc49cf4c1db5b478231ea9d91377ffa98fe95685fca20ba4623212b2f2def4da5b281ed0100b651f6db32112e4017d831c0da668768afa7141d45bbc279f1e0f8735d74395b3";
    const N_ENC: &[u8] = b"d6930820f71fe517bf3259d14d40209b02a5c0d3d61991c731dd7da39f8d69821552e2318d6c9ad897e603887a476ea3162c1205da9ac96f02edf31df049bd55f142134c17d4382a0e78e275345f165fbe8e49cdca6cf5c726c599dd39e09e75e0f330a33121e73976e4facba9cfa001c28b7c96f8134f9981db6750b43a41710f51da4240fe03106c12acb1e7bb53d75ec7256da3fddd0718b89c365410fce61bc7c99b115fb4c3c318081fa7e1b65a37774e8e50c96e8ce2b2cc6b3b367982366a2bf9924c4bafdb3ff5e722258ab705c76d43e5f1f121b984814e98ea2b2b8725cd9bc905c0bc3d75c2a8db70a7153213c39ae371b2b5dc1dafcb19d6fae9";
    const E_ENC: &[u8] = b"010001";
    const D_ENC: &[u8] = b"4e21356983722aa1adedb084a483401c1127b781aac89eab103e1cfc52215494981d18dd8028566d9d499469c25476358de23821c78a6ae43005e26b394e3051b5ca206aa9968d68cae23b5affd9cbb4cb16d64ac7754b3cdba241b72ad6ddfc000facdb0f0dd03abd4efcfee1730748fcc47b7621182ef8af2eeb7c985349f62ce96ab373d2689baeaea0e28ea7d45f2d605451920ca4ea1f0c08b0f1f6711eaa4b7cca66d58a6b916f9985480f90aca97210685ac7b12d2ec3e30a1c7b97b65a18d38a93189258aa346bf2bc572cd7e7359605c20221b8909d599ed9d38164c9c4abf396f897b9993c1e805e574d704649985b600fa0ced8e5427071d7049d";
    let sk = SecretKey(
        RsaPrivateKey::from_components(
            hex_to_biguint(N_ENC),
            hex_to_biguint(E_ENC),
            hex_to_biguint(D_ENC),
            vec![hex_to_biguint(P_ENC), hex_to_biguint(Q_ENC)],
        )
        .unwrap(),
    );
    let public_key = PublicKey(sk.0.to_public_key());

    let rng = &mut thread_rng();

    // Server: Instantiate in-memory keystore and nonce store.
    let issuer_key_store = IssuerMemoryKeyStore::default();
    let origin_key_store = OriginMemoryKeyStore::default();
    let nonce_store = MemoryNonceStore::default();

    // Server: Create servers for issuer and origin
    let issuer_server = IssuerServer::new();
    let origin_server = OriginServer::new();

    // Issuer server: Create a new keypair
    let key_pair = KeyPair {
        sk,
        pk: public_key.clone(),
    };
    let public_key_enc = serialize_public_key(&key_pair.pk);
    let key_id: KeyId = Sha256::digest(public_key_enc).into();
    let token_key_id = *key_id.iter().last().unwrap_or(&0);
    issuer_key_store
        .insert(token_key_id, key_pair.clone())
        .await;

    origin_key_store
        .insert(public_key_to_token_key_id(&public_key), public_key.clone())
        .await;

    // Client: Create client
    let mut client = Client::new(public_key);

    // Generate a challenge
    let token_challenge = TokenChallenge::new(
        TokenType::PublicMetadata,
        "example.com",
        None,
        &["example.com".to_string()],
    );
    let challenge_digest = token_challenge.digest().unwrap();
    let metadata = b"Hello world";
    let protocol = TokenProtocol::PublicMetadata { metadata };

    // Client: Prepare a TokenRequest after having received a challenge
    let (token_request, token_state) = client
        .issue_token_request_protocol(rng, token_challenge, protocol.clone())
        .unwrap();

    // Issuer server: Issue a TokenResponse
    let token_response = issuer_server
        .issue_token_response_protocol(&issuer_key_store, token_request, protocol.clone())
        .await
        .unwrap();

    // Client: Turn the TokenResponse into a Token
    let token = client.issue_token(token_response, &token_state).unwrap();

    // Origin server: Compare the challenge digest
    assert_eq!(token.challenge_digest(), &challenge_digest);

    // Origin server: Redeem the token
    origin_server
        .redeem_token_protocol(
            &origin_key_store,
            &nonce_store,
            token.clone(),
            protocol.clone(),
        )
        .await
        .unwrap();

    // Origin server: Test double spend protection
    assert_eq!(
        origin_server
            .redeem_token_protocol(&origin_key_store, &nonce_store, token, protocol.clone())
            .await,
        Err(RedeemTokenError::DoubleSpending)
    );
}
