//! # Privately Verifiable Tokens

use sha2::digest::OutputSizeUser;
pub use voprf::*;

use crate::auth::authorize::Token;

pub mod request;
pub mod response;
pub mod server;

pub use request::*;
pub use response::*;

/// Privately Verifiable Token alias
pub type PrivateToken<CS> = Token<<<CS as CipherSuite>::Hash as OutputSizeUser>::OutputSize>;
