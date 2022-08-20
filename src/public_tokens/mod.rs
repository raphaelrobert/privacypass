pub mod client;
pub mod server;

use crate::{Nonce, TokenType};

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
