pub mod auth;
pub mod private_tokens;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum TokenType {
    Voprf = 1,
}
