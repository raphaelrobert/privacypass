//! # Batched tokens

use sha2::digest::OutputSizeUser;
use voprf::CipherSuite;

use crate::auth::authorize::Token;

pub mod request;
pub mod response;
pub mod server;

pub use request::*;
pub use response::*;

/// Batched token alias
pub type BatchedToken<CS> = Token<<<CS as CipherSuite>::Hash as OutputSizeUser>::OutputSize>;
