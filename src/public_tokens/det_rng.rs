//! Helper RNG that returns the same set of values for each call to (try_)fill_bytes.

use blind_rsa_signatures::DefaultRng;
use blind_rsa_signatures::reexports::rand::{TryCryptoRng, TryRng};
use std::convert::Infallible;

/// This RNG step is used to generate deterministic values for the nonce, salt,
/// and blind.
#[derive(Debug)]
pub enum RngStep {
    /// The nonce is the first value to be generated.
    Nonce,
    /// The salt is the second value to be generated.
    Salt,
    /// The blind is the third value to be generated.
    Blind,
    /// The additional blind is the fourth value to be generated.
    AdditionalBlind,
}

/// A deterministic RNG that returns the same set of values for each call to
/// (try_)fill_bytes.
#[derive(Debug)]
pub struct DeterministicRng {
    nonce: Vec<u8>,
    salt: Vec<u8>,
    blind: Vec<u8>,
    additional_blind: Option<Vec<u8>>,
    step: RngStep,
}

impl DeterministicRng {
    /// Creates a new `DeterministicRng` with the given nonce, salt, and blind.
    pub fn new(nonce: Vec<u8>, salt: Vec<u8>, blind: Vec<u8>) -> Self {
        Self {
            nonce,
            salt,
            blind,
            additional_blind: None,
            step: RngStep::Nonce,
        }
    }

    /// Returns the nonce.
    pub fn additional_blind(&self) -> Option<&[u8]> {
        self.additional_blind.as_deref()
    }

    fn fill_with_data(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        match self.step {
            RngStep::Nonce => {
                dest.copy_from_slice(&self.nonce);
                self.step = RngStep::Salt;
            }
            RngStep::Salt => {
                dest.copy_from_slice(&self.salt);
                self.step = RngStep::Blind;
            }
            RngStep::Blind => {
                dest.copy_from_slice(&self.blind);
                self.step = RngStep::AdditionalBlind;
            }
            RngStep::AdditionalBlind => {
                let mut ab = [0u8; 256];
                DefaultRng.try_fill_bytes(&mut ab)?;
                dest.copy_from_slice(&ab);
                self.additional_blind = Some(ab.to_vec());
                self.step = RngStep::AdditionalBlind;
            }
        }
        Ok(())
    }
}

impl TryRng for DeterministicRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut buf = [0u8; 4];
        self.fill_with_data(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut buf = [0u8; 8];
        self.fill_with_data(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        self.fill_with_data(dest)
    }
}

impl TryCryptoRng for DeterministicRng {}
