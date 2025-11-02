use blind_rsa_signatures::{KeyPair, Options, PublicKey, SecretKey};
use privacypass::{
    TokenType,
    auth::authenticate::TokenChallenge,
    common::errors::RedeemTokenError,
    public_tokens::{
        TokenRequest, public_key_to_truncated_token_key_id,
        server::{IssuerKeyStore, IssuerServer, OriginKeyStore, OriginServer},
    },
    test_utils::{
        nonce_store::MemoryNonceStore,
        public_memory_store::{IssuerMemoryKeyStore, OriginMemoryKeyStore},
    },
};
use rand::thread_rng;

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
    let public_key = issuer_server
        .create_keypair(rng, &issuer_key_store)
        .await
        .unwrap();

    origin_key_store
        .insert(
            public_key_to_truncated_token_key_id(&public_key),
            public_key.clone(),
        )
        .await;

    // Generate a challenge
    let token_challenge = TokenChallenge::new(
        TokenType::Public,
        "example.com",
        None,
        &["example.com".to_string()],
    );
    let challenge_digest = token_challenge.digest().unwrap();

    // Client: Prepare a TokenRequest after having received a challenge
    let (token_request, token_state) =
        TokenRequest::new(rng, public_key, &token_challenge).unwrap();

    // Issuer server: Issue a TokenResponse
    let token_response = issuer_server
        .issue_token_response(&issuer_key_store, token_request)
        .await
        .unwrap();

    // Client: Turn the TokenResponse into a Token
    let token = token_response.issue_token(&token_state).unwrap();

    // Origin server: Compare the challenge digest
    assert_eq!(token.challenge_digest(), &challenge_digest);

    // Origin server: Redeem the token
    assert!(
        origin_server
            .redeem_token(&origin_key_store, &nonce_store, token.clone())
            .await
            .is_ok()
    );

    // Origin server: Test double spend protection
    assert_eq!(
        origin_server
            .redeem_token(&origin_key_store, &nonce_store, token)
            .await,
        Err(RedeemTokenError::DoubleSpending)
    );
}

#[tokio::test]
async fn redeem_token_supports_multiple_public_keys_per_truncated_id() {
    let rng = &mut thread_rng();

    let issuer_key_store = IssuerMemoryKeyStore::default();
    let origin_key_store = OriginMemoryKeyStore::default();
    let nonce_store = MemoryNonceStore::default();

    let issuer_server = IssuerServer::new();
    let origin_server = OriginServer::new();

    const TRUNCATED_TOKEN_KEY_ID_HEX: &str = "cd";
    const INITIAL_PUBLIC_KEY_SPKI_DER_HEX: &str = "30820152303d06092a864886f70d01010a3030a00d300b0609608648016503040202a11a301806092a864886f70d010108300b0609608648016503040202a2030201300382010f003082010a0282010100abda72d4e29a23d84d1423e567aa9a1e7a6fa10fd6fddb7d2d6806369fe36b3e038bc7dbdb54cc3fd80069e1978feb0d2e7f8c6f3c8dc9358ddb00dd86024d25721e7cb216fef8f8d0d6772e2afffb47312ef593598fbdcd35ada526d36d708eb63352bc7921265df2b69bff1367f5c1f93248e2ff82b9ee8a2cea1755691a4447cb02072cf227a5743d3ee365ebdf40ac54d71c385cfb1e4c8c1cfa827b81438f7bf915235b8a8ceb8826392ca96d551392419366fc2be13654532556da13d50fd630c74c850871d537f6b9583b661165d42f92973dcbd1fb7307cf3fffbee43764f778ca29a6735b081f2060ec50ea1e101fae72ebc2f978c9d341df90d1930203010001";
    const INITIAL_SECRET_KEY_PKCS8_DER_HEX: &str = "308204be020100300d06092a864886f70d0101010500048204a8308204a40201000282010100abda72d4e29a23d84d1423e567aa9a1e7a6fa10fd6fddb7d2d6806369fe36b3e038bc7dbdb54cc3fd80069e1978feb0d2e7f8c6f3c8dc9358ddb00dd86024d25721e7cb216fef8f8d0d6772e2afffb47312ef593598fbdcd35ada526d36d708eb63352bc7921265df2b69bff1367f5c1f93248e2ff82b9ee8a2cea1755691a4447cb02072cf227a5743d3ee365ebdf40ac54d71c385cfb1e4c8c1cfa827b81438f7bf915235b8a8ceb8826392ca96d551392419366fc2be13654532556da13d50fd630c74c850871d537f6b9583b661165d42f92973dcbd1fb7307cf3fffbee43764f778ca29a6735b081f2060ec50ea1e101fae72ebc2f978c9d341df90d193020301000102820101008b424ab96e2300170066e8abb634ce0d12a430bcf837e04bf0a6921a63b85327fe919fd3ee4929f63660276cd277a23e9d4668939f5b3a0876ba585a2a84e4e50a33e05224465b94ad0e8da750dafc51756e9b3bdb609aaa96ebee9fa6c6d166240934eb5bb0dc39573c58eefb57cc13728f27f7229c59750e6d5508b182a8f005511b05dfac53021889ba8c4c1bd96b140ec17d34e4bb6f01051462ac5b92bd89c4b7380fc91f88fd957d50e9de375e10a7cc8400ed453f107903c101e07082122d8cb10be03b8409bf3c189f9fbf179e06f3bd45bdb70f76d2f31d99f6e8facd4408d817ba908feaa4d42fe8f3acf075c9aaa8512576982b7ce73f2686593102818100c659186c3a20b6380653c8ad5487e61c62bca0e1494c7b49a688409d0dbd7176f63d333bfe2752268c26d008d70b2ed974f530d19cc02dddb3baeaeea1246235ee01b6c52499bfc6aedffc1adf17f8bc3f49a2eb5e07c8f4602b598c063cc11ec148b6a947551425e42acdcbae5bc07600b6fd7c896c8a4fd7abb31f3401682902818100ddcde78c0a5120fdc53d7dd6484411a284bb94eb2afba7738614434aeaf40ba86c6772aae0e9640c6fce5796f119f20c61f2e0df1c55c56df8a6dfd54f370c8734754378c2b2a1c874f6c8ecf612bd72654bc614074ccedf101a0e2d69a5487874113932cf48d1fa7f99b4efecd9d103676ee41699af8af8076498d95b5fd35b02818051d3ddd48062906a2a8a142715d17ee844ffa6ab6a8ee7e9e98f1a80f073304530aeecdd1a2be4a34c7c92a4a2fad518173d3427b5b03efbd0b3134ae125de727b3f2fc4c325becd5bc5c1fedffcc6bbfaac094f6a9a719807b8ba979ed71fa0ed826f0105119f5f467336358a3805fd68ac1585743858133a59766b300c488902818100bd7bb0aa7709d5c8559ef18884d5f9c6bfe3cc1596f3c39ab2594f1f8a56903b02d8e121cfe0328359648a793d616fe15a2ff621440096181b8adbbf4bdbf84cece89c8a66b1d9f9f8c9f6de505db4102d2f2d7960bf221f778efabb9afc034c3bc396fcac0e46abdc244069930a853f86363a8e801e71f6efc1e5be120c6bef0281807a1d4af802d8e4c7b92de8e1bd90f73af328afe7d72a862a2c42dbeb16a51912a6697bd40cbb5674f790aba4473e33cb38b9efc9194c57fb392dd6e31e1ec6d31f7d99865ff15910c17d407de4be39972c6c90d7710bcfb1afa1cce4cf4b29d037577769fcc251a005eef7e74ed9dfacc426fd1fa79b57dbca9168d2752aa830";
    const ROTATED_PUBLIC_KEY_SPKI_DER_HEX: &str = "30820152303d06092a864886f70d01010a3030a00d300b0609608648016503040202a11a301806092a864886f70d010108300b0609608648016503040202a2030201300382010f003082010a0282010100d0b87841943c6b4923e9d05733e32733eaebad32b89337d6aca739a4aeaf568eedad36b3b1ef3b01c540b1034780c2ae86d9becfae5fbc0ca1a8fd0b9cd0e4fdc109a4963e1c64aed8c08f294460f2042440fbb7646a939866fd1dbbde91786bec0cbdc88a4baf3915b303f0ed9e86cfbf38b922990da82e68cac72714a6d5f0fed457969ce3736082bf2016cca0c93396eb69765a48008043bf583a86a932ac8fb42939da54c48d4801732a902ddf229e3cd60dd0ccb0a91569b104d1bbc75e3514edb9afa56d144396e56b86c49ee58d0710d38671153735605a29fb37b6289fe7833fca44224d5b02a0a320f7726b84fea229409ebbd1784da1d5972063cb0203010001";
    const ROTATED_SECRET_KEY_PKCS8_DER_HEX: &str = "308204be020100300d06092a864886f70d0101010500048204a8308204a40201000282010100d0b87841943c6b4923e9d05733e32733eaebad32b89337d6aca739a4aeaf568eedad36b3b1ef3b01c540b1034780c2ae86d9becfae5fbc0ca1a8fd0b9cd0e4fdc109a4963e1c64aed8c08f294460f2042440fbb7646a939866fd1dbbde91786bec0cbdc88a4baf3915b303f0ed9e86cfbf38b922990da82e68cac72714a6d5f0fed457969ce3736082bf2016cca0c93396eb69765a48008043bf583a86a932ac8fb42939da54c48d4801732a902ddf229e3cd60dd0ccb0a91569b104d1bbc75e3514edb9afa56d144396e56b86c49ee58d0710d38671153735605a29fb37b6289fe7833fca44224d5b02a0a320f7726b84fea229409ebbd1784da1d5972063cb02030100010282010046046c0b0bd04ce9474beb61257de12bd075e92f27adf34067c0dd5c7a6145774312255498af392b39e19ec00bdf8cef813b508058edb2a6c6206b6ad6db58c62b58b1c6d8e52b7d6027109f7659d33642772e39f24cb260a0c3ee929472566455d65c6006cca6e64e7a342b417b399c3d78a8da8b5f8278b71cb73c4bf83fb232938044cda41fe260e42675b4b124ea2b4fee4549f3dc1557ac64da4d0fe2d2b961bf1b58a529dc96e1ea469052feb54702af43c5d73bd67d7e5ec63b34b3db53cba0c6fae490e8a11d0bc8db4832f40db7def7ece49f9a9b2de56be82e85082df2eda06a603ac09784a3f4c59914364e2a25ccce110a8aea03d0fa79093cd102818100e0a717e71004386fc832363d18e3164c0b47b5d6c8a1a309fc999f6f9a98a6c070a4fbed654f4add9d1fdfc0b1cee25b9987cd64b8811cd1cba39762830ea06f51238509fc4f57c129d109eede3a764918006efe11bbe32da38f7345da4f44e955f8909cd4f7f7bc5c0820bf9a311a0f324a86181c21fc426b6fd76d4649fdd302818100edd842416e605c04158b65481c93900ca73941195aa6ef6bc71026853e5d48ab5d6ead864f140c506b8abb148248093ecb82c31d8c609074a835f3c27e0eccec1f8409f9e3e5f66e148c61dd03a1e60ca46553c8cfd16d56d2074c0f22b53772cab1e0dd0443bbfb86ce7d7f344fc3049a25d1110a0e7839ef80a8db5c7f2f2902818069f585e99efd4e9d32a0b44266fd9ce3ab225c9afcb07854da869ed3a5e840265e3b02f43aa786993665f5444ed9549c7db2b6e6bdbb701b67e03623e9cab95327c30819e89e87b67d01b29caec68649fd7f1edac90484a75f10e6fed87430fd99660ed759ffc722598a1fe01f5aef7ea16ad30a86226577f272a2fa507fcfaf028181008aa70070de64841fc9637ac6a00a11f69e618d26b7a70b79bc111933a1d885ad888925d55f3223bf9a01c4efbec739c486a513139dab096b4848337315439188b112ab3226fdff3bcaf4cf742552f326398bec5ceb717e1917d5332cbba202d20381d0c167640929273c2702c9bf19c40c0cb1a50a44c727970c5ce38c37848902818100ba3f80decaef23ba192b813334325cdbb284cfede64ebc39d3ef1a09c672f75f6dced39228c8f791016d747974f64c5e3176f3c7fdd4d81641b321afaa29a9dce3d3f09b8698430f9a9836eeb3d1eea79c47407398e421eacdfce81e4d272e772e37f09fe145ce72e03179e7e1d7500376b9fa19b69af62948e9e470d3567ca9";

    let decode_hex = |s: &str| -> Vec<u8> { hex::decode(s).expect("valid hex") };

    let truncated_token_key_id =
        u8::from_str_radix(TRUNCATED_TOKEN_KEY_ID_HEX, 16).expect("valid truncated id");
    let options = Options::default();

    let initial_public_key =
        PublicKey::from_spki(&decode_hex(INITIAL_PUBLIC_KEY_SPKI_DER_HEX), Some(&options))
            .expect("initial public key should decode");
    let initial_secret_key = SecretKey::from_der(&decode_hex(INITIAL_SECRET_KEY_PKCS8_DER_HEX))
        .expect("initial secret key should decode");
    let initial_keypair = KeyPair {
        pk: initial_public_key.clone(),
        sk: initial_secret_key,
    };
    assert_eq!(
        truncated_token_key_id,
        public_key_to_truncated_token_key_id(&initial_keypair.pk)
    );
    issuer_key_store
        .insert(truncated_token_key_id, initial_keypair.clone())
        .await;
    origin_key_store
        .insert(truncated_token_key_id, initial_public_key.clone())
        .await;

    let token_challenge = TokenChallenge::new(
        TokenType::Public,
        "example.com",
        None,
        &["example.com".to_string()],
    );

    let (token_request, token_state) =
        TokenRequest::new(rng, initial_public_key, &token_challenge).unwrap();
    let token_response = issuer_server
        .issue_token_response(&issuer_key_store, token_request)
        .await
        .unwrap();
    let token = token_response.issue_token(&token_state).unwrap();

    let rotated_public_key =
        PublicKey::from_spki(&decode_hex(ROTATED_PUBLIC_KEY_SPKI_DER_HEX), Some(&options))
            .expect("rotated public key should decode");
    let rotated_secret_key = SecretKey::from_der(&decode_hex(ROTATED_SECRET_KEY_PKCS8_DER_HEX))
        .expect("rotated secret key should decode");
    let rotated_keypair = KeyPair {
        pk: rotated_public_key.clone(),
        sk: rotated_secret_key,
    };
    assert_eq!(
        truncated_token_key_id,
        public_key_to_truncated_token_key_id(&rotated_keypair.pk)
    );

    origin_key_store
        .insert(truncated_token_key_id, rotated_public_key)
        .await;

    let stored_keys = origin_key_store.get(&truncated_token_key_id).await;
    assert_eq!(stored_keys.len(), 2);

    origin_server
        .redeem_token(&origin_key_store, &nonce_store, token)
        .await
        .unwrap();
}
