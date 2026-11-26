//! # Amortized tokens

use sha2::digest::OutputSizeUser;
#[cfg(any(feature = "p384", feature = "ristretto255"))]
use voprf::CipherSuite;

use crate::auth::authorize::Token;

pub mod request;
pub mod response;
pub mod server;

pub use request::*;
pub use response::*;

/// Amortized token alias
pub type AmortizedToken<CS> = Token<<<CS as CipherSuite>::Hash as OutputSizeUser>::OutputSize>;
