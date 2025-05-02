//! # Batched tokens

pub mod client;
pub mod server;

use std::fmt::Debug;

use sha2::digest::OutputSizeUser;
use tls_codec::{Deserialize, Serialize, Size};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
use typenum::Unsigned;
pub use voprf::*;

use crate::{
    PPCipherSuite, TokenType, TruncatedTokenKeyId, auth::authorize::Token,
    common::errors::SerializationError,
};

/// Batched token alias
pub type BatchedToken<CS> = Token<<<CS as CipherSuite>::Hash as OutputSizeUser>::OutputSize>;

/// Blinded element as specified in the spec:
///
/// ```c
/// struct {
///     uint8_t blinded_element[Ne];
/// } BlindedElement;
/// ```
#[derive(Debug)]
pub struct BlindedElement<CS: PPCipherSuite> {
    _marker: std::marker::PhantomData<CS>,
    blinded_element: Vec<u8>,
}

impl<CS: PPCipherSuite> Size for BlindedElement<CS> {
    fn tls_serialized_len(&self) -> usize {
        <<CS::Group as Group>::ElemLen as Unsigned>::USIZE
    }
}

impl<CS: PPCipherSuite> Serialize for BlindedElement<CS> {
    fn tls_serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::result::Result<usize, tls_codec::Error> {
        writer.write_all(&self.blinded_element)?;
        Ok(self.blinded_element.len())
    }
}

impl<CS: PPCipherSuite> Deserialize for BlindedElement<CS> {
    fn tls_deserialize<R: std::io::Read>(
        bytes: &mut R,
    ) -> std::result::Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let mut blinded_element = vec![0u8; <<CS::Group as Group>::ElemLen as Unsigned>::USIZE];
        bytes.read_exact(&mut blinded_element)?;
        Ok(BlindedElement {
            _marker: std::marker::PhantomData,
            blinded_element,
        })
    }
}

/// Token request as specified in the spec:
///
/// ```c
/// struct {
///     uint16_t token_type = 0xF901;
///     uint8_t truncated_token_key_id;
///     BlindedElement blinded_element[Nr];
/// } TokenRequest;
/// ```
#[derive(Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct TokenRequest<CS: PPCipherSuite> {
    token_type: TokenType,
    truncated_token_key_id: TruncatedTokenKeyId,
    blinded_elements: Vec<BlindedElement<CS>>,
}

impl<CS: PPCipherSuite> TokenRequest<CS> {
    /// Returns the number of blinded elements
    #[must_use]
    pub fn nr(&self) -> usize {
        self.blinded_elements.len()
    }
}

/// Evaluated element as specified in the spec:
///
/// ```c
/// struct {
///     uint8_t evaluated_element[Ne];
/// } EvaluatedElement;
/// ```

#[derive(Debug, PartialEq)]
pub struct EvaluatedElement<CS: PPCipherSuite> {
    _marker: std::marker::PhantomData<CS>,
    evaluated_element: Vec<u8>,
}

impl<CS: PPCipherSuite> Size for EvaluatedElement<CS> {
    fn tls_serialized_len(&self) -> usize {
        <<CS::Group as Group>::ElemLen as Unsigned>::USIZE
    }
}

impl<CS: PPCipherSuite> Serialize for EvaluatedElement<CS> {
    fn tls_serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::result::Result<usize, tls_codec::Error> {
        writer.write_all(&self.evaluated_element)?;
        Ok(self.evaluated_element.len())
    }
}

impl<CS: PPCipherSuite> Deserialize for EvaluatedElement<CS> {
    fn tls_deserialize<R: std::io::Read>(
        bytes: &mut R,
    ) -> std::result::Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let mut evaluated_element = vec![0u8; <<CS::Group as Group>::ElemLen as Unsigned>::USIZE];
        bytes.read_exact(&mut evaluated_element)?;
        Ok(EvaluatedElement {
            _marker: std::marker::PhantomData,
            evaluated_element,
        })
    }
}

/// Token response as specified in the spec:
///
/// ```c
/// struct {
///     EvaluatedElement evaluated_elements[Nr];
///     uint8_t evaluated_proof[Ns + Ns];
///  } TokenResponse;
/// ```
#[derive(Debug)]
pub struct TokenResponse<CS: PPCipherSuite> {
    _marker: std::marker::PhantomData<CS>,
    evaluated_elements: Vec<EvaluatedElement<CS>>,
    evaluated_proof: Vec<u8>,
}

impl<CS: PPCipherSuite> Size for TokenResponse<CS> {
    fn tls_serialized_len(&self) -> usize {
        let len = 2 * <<CS::Group as Group>::ScalarLen as Unsigned>::USIZE;
        self.evaluated_elements.tls_serialized_len() + len
    }
}

impl<CS: PPCipherSuite> Deserialize for TokenResponse<CS> {
    fn tls_deserialize<R: std::io::Read>(
        bytes: &mut R,
    ) -> std::result::Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let evaluated_elements = Vec::<EvaluatedElement<CS>>::tls_deserialize(bytes)?;
        let len = 2 * <<CS::Group as Group>::ScalarLen as Unsigned>::USIZE;
        // read len bytes
        let mut evaluated_proof = vec![0u8; len];
        bytes.read_exact(&mut evaluated_proof)?;
        Ok(TokenResponse {
            _marker: std::marker::PhantomData,
            evaluated_elements,
            evaluated_proof,
        })
    }
}

impl<CS: PPCipherSuite> Serialize for TokenResponse<CS> {
    fn tls_serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::result::Result<usize, tls_codec::Error> {
        let written = self.evaluated_elements.tls_serialize(writer)?;
        writer.write_all(&self.evaluated_proof)?;
        Ok(written + self.evaluated_proof.len())
    }
}

impl<CS: PPCipherSuite> TokenResponse<CS>
where
    <<CS as voprf::CipherSuite>::Group as voprf::Group>::ScalarLen: std::ops::Add,
    <<<CS as voprf::CipherSuite>::Group as voprf::Group>::ScalarLen as std::ops::Add>::Output:
        generic_array::ArrayLength<u8>,
{
    /// Create a new `TokenResponse` from a byte slice.
    ///
    /// # Errors
    /// Returns `SerializationError::InvalidData` if the byte slice is not a
    /// valid `TokenResponse`.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        let mut bytes = bytes;
        Self::tls_deserialize(&mut bytes).map_err(|_| SerializationError::InvalidData)
    }

    #[cfg(feature = "kat")]
    /// Returns the evaluated elements
    #[must_use]
    pub fn evaluated_elements(&self) -> &[EvaluatedElement<CS>] {
        &self.evaluated_elements
    }
}
