pub mod client;
pub mod server;

pub use voprf::*;

use crate::TokenType;

pub type KeyId = u8;
pub type Nonce = [u8; 32];

pub struct TokenInput {
    pub token_type: TokenType,
    pub nonce: [u8; 32],
    pub context: Vec<u8>,
    pub key_id: KeyId,
}

impl TokenInput {
    pub fn new(token_type: TokenType, nonce: [u8; 32], context: Vec<u8>, key_id: KeyId) -> Self {
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
        token_input.extend_from_slice((self.token_type as u16).to_be_bytes().as_slice());
        token_input.extend_from_slice(self.nonce.as_slice());
        token_input.extend_from_slice(self.context.as_slice());
        token_input.push(self.key_id);
        token_input
    }
}

// struct {
//     uint16_t token_type = 0x0001;
//     uint8_t token_key_id;
//     uint8_t blinded_msg[Ne];
//  } TokenRequest;

pub struct TokenRequest {
    token_type: TokenType,
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
    token_type: TokenType,
    nonce: Nonce,
    challenge_digest: Vec<u8>,
    token_key_id: KeyId,
    authenticator: Vec<u8>,
}

impl Token {
    pub fn challenge_digest(&self) -> &[u8] {
        &self.challenge_digest
    }
}
