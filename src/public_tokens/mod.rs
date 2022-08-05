pub mod client;
pub mod server;

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
        // token_input = concat(0x0001, nonce, challenge_digest, key_id)
        let mut token_input: Vec<u8> = Vec::new();
        token_input.extend_from_slice((self.token_type as u16).to_be_bytes().as_slice());
        token_input.extend_from_slice(self.nonce.as_slice());
        token_input.extend_from_slice(self.challenge_digest.as_slice());
        token_input.push(self.key_id);
        token_input
    }
}

// struct {
//     uint16_t token_type = 0x0002;
//     uint8_t token_key_id;
//     uint8_t blinded_msg[Nk];
//  } TokenRequest;

pub struct TokenRequest {
    token_type: TokenType,
    token_key_id: u8,
    blinded_msg: Vec<u8>,
}

// struct {
//     uint8_t blind_sig[Nk];
//  } TokenResponse;

pub struct TokenResponse {
    blind_sig: Vec<u8>,
}
