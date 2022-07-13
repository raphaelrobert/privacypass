use generic_array::GenericArray;
use rand::{rngs::OsRng, Rng, RngCore};
//use serde::ser::Serialize;
use sha2::{
    digest::{
        core_api::BlockSizeUser,
        typenum::{IsLess, IsLessOrEqual, U256},
        OutputSizeUser,
    },
    Digest, Sha256,
};
use std::collections::{HashMap, HashSet};
use voprf::*;

type KeyId = u8;

pub struct Client<CS: CipherSuite>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    rng: OsRng,
    key_id: u8,
    public_key: <CS::Group as Group>::Elem,
}

impl<CS: CipherSuite> Client<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    pub fn new(key_id: u8, public_key: <CS::Group as Group>::Elem) -> Self {
        Self {
            rng: OsRng,
            key_id,
            public_key,
        }
    }

    pub fn issue_token_request(&mut self, challenge: &[u8]) -> (TokenRequest, TokenState<CS>) {
        let nonce: [u8; 32] = self.rng.gen();
        let context = Sha256::digest(challenge).to_vec();

        // nonce = random(32)
        // context = SHA256(challenge)
        // token_input = concat(0x0001, nonce, context, key_id)
        // blind, blinded_element = client_context.Blind(token_input)

        let token_input = TokenInput::new(1, nonce, context.clone(), self.key_id);

        let blinded_element =
            VoprfClient::<CS>::blind(&token_input.serialize(), &mut self.rng).unwrap();
        let token_request = TokenRequest {
            token_type: 1,
            token_key_id: 1,
            blinded_msg: blinded_element.message.serialize().to_vec(),
        };
        let token_state = TokenState {
            client: blinded_element.state,
            token_input,
            challenge_digest: context,
        };
        (token_request, token_state)
    }

    pub fn issue_token(&self, token_response: TokenResponse, token_state: TokenState<CS>) -> Token
    where
        <CS::Hash as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    {
        let evaluation_element =
            EvaluationElement::deserialize(&token_response.evaluate_msg).unwrap();
        let proof = Proof::deserialize(&token_response.evaluate_proof).unwrap();
        let token_input = token_state.token_input.serialize();
        // authenticator = client_context.Finalize(token_input, blind, evaluated_element, blinded_element, proof)
        let authenticator = token_state
            .client
            .finalize(&token_input, &evaluation_element, &proof, self.public_key)
            .unwrap()
            .to_vec();
        Token {
            token_type: 1,
            nonce: token_state.token_input.nonce.to_vec(),
            challenge_digest: token_state.challenge_digest,
            token_key_id: token_state.token_input.key_id,
            authenticator,
        }
    }
}

pub struct TokenInput {
    pub token_type: u16,
    pub nonce: [u8; 32],
    pub context: Vec<u8>,
    pub key_id: KeyId,
}

impl TokenInput {
    pub fn new(token_type: u16, nonce: [u8; 32], context: Vec<u8>, key_id: KeyId) -> Self {
        Self {
            token_type,
            nonce,
            context,
            key_id,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        // token_input = concat(0x0001, nonce, context, key_id)
        let mut token_input: Vec<u8> = Vec::new();
        token_input.extend_from_slice(self.token_type.to_be_bytes().as_slice());
        token_input.extend_from_slice(self.nonce.as_slice());
        token_input.extend_from_slice(self.context.as_slice());
        token_input.push(self.key_id);
        token_input
    }
}

pub struct TokenState<CS: CipherSuite>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    client: VoprfClient<CS>,
    token_input: TokenInput,
    challenge_digest: Vec<u8>,
}

// struct {
//     uint16_t token_type = 0x0001;
//     uint8_t token_key_id;
//     uint8_t blinded_msg[Ne];
//  } TokenRequest;

pub struct TokenRequest {
    token_type: u16,
    token_key_id: u8,
    blinded_msg: Vec<u8>,
}

// struct {
//     uint8_t evaluate_msg[Nk];
//     uint8_t evaluate_proof[Ns+Ns];
//  } TokenResponse;

pub struct TokenResponse {
    evaluate_msg: Vec<u8>,
    evaluate_proof: Vec<u8>,
}

// struct {
//     uint16_t token_type = 0x0001
//     uint8_t nonce[32];
//     uint8_t challenge_digest[32];
//     uint8_t token_key_id[32];
//     uint8_t authenticator[Nk];
// } Token;

#[derive(Clone)]
pub struct Token {
    token_type: u16,
    nonce: Vec<u8>,
    challenge_digest: Vec<u8>,
    token_key_id: KeyId,
    authenticator: Vec<u8>,
}

// TODO:
// - error handling
// - traits for persistence (keystore, double spending protection)
pub struct Server<CS: CipherSuite>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    rng: OsRng,
    keys: HashMap<KeyId, VoprfServer<CS>>,
    nonces: HashSet<[u8; 32]>,
}

impl<CS: CipherSuite> Server<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    <CS::Group as Group>::ScalarLen: std::ops::Add,
    <<CS::Group as Group>::ScalarLen as std::ops::Add>::Output:
        sha2::digest::generic_array::ArrayLength<u8>,
{
    pub fn new() -> Self {
        Self {
            rng: OsRng,
            keys: HashMap::new(),
            nonces: HashSet::new(),
        }
    }

    pub fn create_keypair(&mut self, key_id: KeyId) {
        let mut seed = GenericArray::<_, <CS::Group as Group>::ScalarLen>::default();
        self.rng.fill_bytes(&mut seed);
        let server = VoprfServer::<CS>::new_from_seed(&seed, b"PrivacyPass").unwrap();
        self.keys.insert(key_id, server);
    }

    pub fn get_key(&self, key_id: KeyId) -> Option<<CS::Group as Group>::Elem> {
        self.keys.get(&key_id).map(|s| s.get_public_key())
    }

    pub fn list_keys(&self) -> Vec<KeyId> {
        self.keys.keys().cloned().collect()
    }

    pub fn remove_key(&mut self, key_id: KeyId) {
        self.keys.remove(&key_id);
    }

    pub fn issue_token_response(&mut self, token_request: TokenRequest) -> TokenResponse {
        assert_eq!(token_request.token_type, 1);
        let server = self.keys.get_mut(&token_request.token_key_id).unwrap();
        let blinded_element =
            BlindedElement::<CS>::deserialize(&token_request.blinded_msg).unwrap();
        let evaluated_result = server.blind_evaluate(&mut self.rng, &blinded_element);
        TokenResponse {
            evaluate_msg: evaluated_result.message.serialize().to_vec(),
            evaluate_proof: evaluated_result.proof.serialize().to_vec(),
        }
    }

    pub fn redeem_token(&mut self, token: Token) -> bool {
        // TODO: Validate token fields
        let nonce: [u8; 32] = token.nonce.as_slice().try_into().unwrap();
        if self.nonces.contains(&nonce) {
            return false;
        }
        let token_input = TokenInput {
            token_type: token.token_type,
            nonce,
            context: token.challenge_digest,
            key_id: token.token_key_id,
        };
        let server = self.keys.get(&token.token_key_id).unwrap();
        let token_authenticator = server.evaluate(&token_input.serialize()).unwrap().to_vec();
        if token.authenticator == token_authenticator {
            self.nonces.insert(nonce);
            true
        } else {
            false
        }
    }
}
