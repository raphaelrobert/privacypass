//! Helper RNG that returns the same set of values for each call to (try_)fill_bytes.

use rand::{rngs::OsRng, CryptoRng, Error, RngCore};

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

    fn fill_with_data(&mut self, dest: &mut [u8]) {
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
                OsRng.fill_bytes(&mut ab);
                dest.copy_from_slice(&ab);
                self.additional_blind = Some(ab.to_vec());
                self.step = RngStep::AdditionalBlind;
            }
        }
    }
}

impl RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }

    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.fill_with_data(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_with_data(dest);
        Ok(())
    }
}

impl CryptoRng for DeterministicRng {}
