//! # Privately Verifiable Tokens

pub mod client;
pub mod server;

use sha2::digest::OutputSizeUser;
use tls_codec::{Deserialize, Serialize, Size};
use typenum::Unsigned;
pub use voprf::*;

use crate::{
    Nonce, PPCipherSuite, TokenType, TruncatedTokenKeyId, auth::authorize::Token,
    common::errors::SerializationError,
};

/// Privately Verifiable Token alias
pub type PrivateToken<CS> = Token<<<CS as CipherSuite>::Hash as OutputSizeUser>::OutputSize>;

/// Token request as specified in the spec:
///
/// ```c
/// struct {
///     uint16_t token_type = 0x0001;
///     uint8_t truncated_token_key_id;
///     uint8_t blinded_msg[Ne];
///  } TokenRequest;
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct TokenRequest<CS: PPCipherSuite> {
    _marker: std::marker::PhantomData<CS>,
    token_type: TokenType,
    truncated_token_key_id: u8,
    blinded_msg: Vec<u8>,
}

impl<CS: PPCipherSuite> Size for TokenRequest<CS> {
    fn tls_serialized_len(&self) -> usize {
        let len = <<CS::Group as Group>::ElemLen as Unsigned>::USIZE;
        self.token_type.tls_serialized_len()
            + self.truncated_token_key_id.tls_serialized_len()
            + len
    }
}

impl<CS: PPCipherSuite> Serialize for TokenRequest<CS> {
    fn tls_serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::result::Result<usize, tls_codec::Error> {
        self.token_type.tls_serialize(writer)?;
        self.truncated_token_key_id.tls_serialize(writer)?;
        writer.write_all(&self.blinded_msg)?;
        Ok(self.token_type.tls_serialized_len()
            + self.truncated_token_key_id.tls_serialized_len()
            + self.blinded_msg.len())
    }
}

impl<CS: PPCipherSuite> Deserialize for TokenRequest<CS> {
    fn tls_deserialize<R: std::io::Read>(
        bytes: &mut R,
    ) -> std::result::Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let token_type = TokenType::tls_deserialize(bytes)?;
        let truncated_token_key_id = TruncatedTokenKeyId::tls_deserialize(bytes)?;
        let mut blinded_msg = vec![0u8; <<CS::Group as Group>::ElemLen as Unsigned>::USIZE];
        bytes.read_exact(&mut blinded_msg)?;
        Ok(TokenRequest {
            _marker: std::marker::PhantomData,
            token_type,
            truncated_token_key_id,
            blinded_msg,
        })
    }
}

/// Token response as specified in the spec:
///
/// ```c
/// struct {
///     uint8_t evaluate_msg[Ne];
///     uint8_t evaluate_proof[Ns+Ns];
///  } TokenResponse;
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct TokenResponse<CS: PPCipherSuite> {
    _marker: std::marker::PhantomData<CS>,
    evaluate_msg: Vec<u8>,
    evaluate_proof: Vec<u8>,
}

impl<CS: PPCipherSuite> TokenResponse<CS> {
    /// Create a new `TokenResponse` from a byte slice.
    ///
    /// # Errors
    /// Returns `SerializationError::InvalidData` if the byte slice is not valid.
    pub fn try_from_bytes(mut bytes: &[u8]) -> Result<Self, SerializationError> {
        Self::tls_deserialize(&mut bytes).map_err(|_| SerializationError::InvalidData)
    }

    #[cfg(feature = "kat")]
    /// Returns the evaluated message
    #[must_use]
    pub fn evaluate_msg(&self) -> &[u8] {
        &self.evaluate_msg
    }
}

impl<CS: PPCipherSuite> Size for TokenResponse<CS> {
    fn tls_serialized_len(&self) -> usize {
        let len = <<CS::Group as Group>::ElemLen as Unsigned>::USIZE;
        let proof_len = <<CS::Group as Group>::ScalarLen as Unsigned>::USIZE;
        len + 2 * proof_len
    }
}

impl<CS: PPCipherSuite> Serialize for TokenResponse<CS> {
    fn tls_serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::result::Result<usize, tls_codec::Error> {
        writer.write_all(&self.evaluate_msg)?;
        writer.write_all(&self.evaluate_proof)?;
        Ok(self.evaluate_msg.len() + self.evaluate_proof.len())
    }
}

impl<CS: PPCipherSuite> Deserialize for TokenResponse<CS> {
    fn tls_deserialize<R: std::io::Read>(
        bytes: &mut R,
    ) -> std::result::Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let mut evaluate_msg = vec![0u8; <<CS::Group as Group>::ElemLen as Unsigned>::USIZE];
        bytes.read_exact(&mut evaluate_msg)?;
        let mut evaluate_proof =
            vec![0u8; 2 * <<CS::Group as Group>::ScalarLen as Unsigned>::USIZE];
        bytes.read_exact(&mut evaluate_proof)?;
        Ok(TokenResponse {
            _marker: std::marker::PhantomData,
            evaluate_msg,
            evaluate_proof,
        })
    }
}
