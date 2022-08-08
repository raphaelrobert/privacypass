pub mod client;
pub mod server;

pub use voprf::*;

use crate::{ChallengeDigest, KeyId, Nonce, TokenType};

pub struct TokenInput {
    pub token_type: TokenType,
    pub nonce: Nonce,
    pub challenge_digest: ChallengeDigest,
    pub key_id: KeyId,
}

impl TokenInput {
    pub fn new(
        token_type: TokenType,
        nonce: Nonce,
        challenge_digest: ChallengeDigest,
        key_id: KeyId,
    ) -> Self {
        Self {
            token_type,
            nonce,
            challenge_digest,
            key_id,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        // token_input = concat(0x0003, nonce, challenge_digest, key_id)
        let mut token_input: Vec<u8> = Vec::new();
        token_input.extend_from_slice((self.token_type as u16).to_be_bytes().as_slice());
        token_input.extend_from_slice(self.nonce.as_slice());
        token_input.extend_from_slice(self.challenge_digest.as_slice());
        token_input.push(self.key_id);
        token_input
    }
}

// struct {
//     uint8_t blinded_element[Ne];
// } BlindedElement;

pub struct BlindedElement {
    blinded_element: Vec<u8>,
}

// struct {
//     uint16_t token_type = 0x0003;
//     uint8_t token_key_id;
//     BlindedElement blinded_element[Nr];
// } TokenRequest;

pub struct TokenRequest {
    token_type: TokenType,
    token_key_id: u8,
    blinded_elements: Vec<BlindedElement>,
}

// struct {
//     uint8_t evaluated_element[Ne];
// } EvaluatedElement;

pub struct EvaluatedElement {
    evaluated_element: Vec<u8>,
}

// struct {
//     EvaluatedElement evaluated_elements[Nr];
//     uint8_t evaluated_proof[Ns + Ns];
//  } TokenResponse;

pub struct TokenResponse {
    evaluated_elements: Vec<EvaluatedElement>,
    evaluated_proof: Vec<u8>,
}
