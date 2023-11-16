//! # Publicly Verifiable Tokens

use blind_rsa_signatures::reexports::rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use blind_rsa_signatures::SecretKey;
use sha2::{Digest, Sha256};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
use typenum::U64;

use crate::{auth::authorize::Token, KeyId, Nonce, TokenKeyId, TokenType};

pub mod client;
pub mod server;

/// Publicly Verifiable Token alias
pub type PublicToken = Token<U64>;
pub use blind_rsa_signatures::PublicKey;

use self::server::serialize_public_key;

/// Size of the authenticator
pub const NK: usize = 256;

/// Converts a public key to a token key ID
pub fn public_key_to_token_key_id(public_key: &PublicKey) -> TokenKeyId {
    key_id_to_token_key_id(&public_key_to_key_id(public_key))
}

fn public_key_to_key_id(public_key: &PublicKey) -> KeyId {
    let public_key = serialize_public_key(public_key);

    Sha256::digest(public_key).into()
}

fn key_id_to_token_key_id(key_id: &KeyId) -> TokenKeyId {
    *key_id.iter().last().unwrap_or(&0)
}

/// Token request as specified in the spec:
///
/// ```c
/// struct {
///     uint16_t token_type = 0x0002;
///     uint8_t token_key_id;
///     uint8_t blinded_msg[Nk];
///  } TokenRequest;
/// ```
#[derive(Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct TokenRequest {
    token_type: TokenType,
    token_key_id: u8,
    blinded_msg: [u8; NK],
}

/// Token response as specified in the spec:
///
/// ```c
/// struct {
///     uint8_t blind_sig[Nk];
///  } TokenResponse;
/// ```
#[derive(Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct TokenResponse {
    blind_sig: [u8; NK],
}

fn augment_public_key(public_key: &PublicKey, metadata: &[u8]) -> PublicKey {
    use blind_rsa_signatures::reexports::rsa::PublicKeyParts;

    // expandLen = ceil((ceil(log2(\lambda)) + k) / 8), where k is the security parameter of the suite (e.g., k = 128).
    // We stretch the input metadata beyond \lambda bits s.t. the output bytes are indifferentiable from truly random bytes
    let lambda = public_key.0.n().bits() / 2;
    let expand_len = (lambda + 128) / 8;
    let hkdf_salt = public_key.0.n().to_bytes_be();
    let mut hkdf_input = b"key".to_vec();
    hkdf_input.extend_from_slice(metadata);
    hkdf_input.push(0);

    let hkdf = hkdf::Hkdf::<sha2::Sha384>::new(Some(&hkdf_salt), &hkdf_input);
    let mut bytes = vec![0u8; expand_len];
    hkdf.expand(b"PBRSA", &mut bytes).unwrap();

    // H_MD(D) = 1 || G(x), where G(x) is output of length \lambda-2 bits
    // We do this by sampling \lambda bits, clearing the top two bits (so the output is \lambda-2 bits)
    // and setting the bottom bit (so the result is odd).
    bytes[0] &= 0b00111111;
    bytes[(lambda / 8) - 1] |= 1;
    let hmd = BigUint::from_bytes_be(&bytes[..lambda / 8]);

    // The public exponent will be significantly larger than a typical RSA
    // public key as a result of this augmentation.
    PublicKey(RsaPublicKey::new_unchecked(public_key.0.n().clone(), hmd))
}

// augmentPrivateKey tweaks the private key using the metadata as input.
//
// See the specification for more details:
// https://datatracker.ietf.org/doc/html/draft-amjad-cfrg-partially-blind-rsa-00#name-private-key-augmentation
fn augment_private_key(secret_key: &SecretKey, metadata: &[u8]) -> SecretKey {
    use blind_rsa_signatures::reexports::rsa::PublicKeyParts;
    use num_bigint_dig::traits::ModInverse;

    let [p, q, ..] = secret_key.primes() else {
        panic!("too few primes")
    };
    let one = BigUint::from_slice_native(&[1]);
    // pih(N) = (p-1)(q-1)
    let pm1 = p - &one;
    let qm1 = q - one;
    let phi = pm1 * qm1;

    // d = e^-1 mod phi(N)
    let pk = augment_public_key(&PublicKey(secret_key.to_public_key()), metadata);
    let big_e = pk.e() % &phi;
    let d = big_e.mod_inverse(phi).unwrap().to_biguint().unwrap();
    SecretKey(
        RsaPrivateKey::from_components(
            pk.n().clone(),
            pk.e().clone(),
            d,
            secret_key.primes().to_vec(),
        )
        .unwrap(),
    )
}

fn encode_message_metadata(message: &[u8], metadata: &[u8]) -> Vec<u8> {
    [
        b"msg",
        &(metadata.len() as u32).to_be_bytes()[..],
        metadata,
        message,
    ]
    .iter()
    .flat_map(|b| b.into_iter().copied())
    .collect()
}

/// Token issuance protocol to be used by servers and clients.
#[derive(Clone, Debug)]
pub enum TokenProtocol<'a> {
    /// Privacy Pass issuance protocol
    Basic,
    /// Privacy Pass issuance with Public Metadata
    PublicMetadata {
        /// A reference to the public metadata, cryptographically bound to
        /// the generated token.
        metadata: &'a [u8],
    },
}

impl<'a> Default for TokenProtocol<'a> {
    fn default() -> Self {
        TokenProtocol::Basic
    }
}

impl<'a> TokenProtocol<'a> {
    /// Returns the token type assigned to this variant of the protocol.
    pub fn token_type(&self) -> TokenType {
        match self {
            TokenProtocol::Basic => TokenType::Public,
            TokenProtocol::PublicMetadata { .. } => TokenType::PublicMetadata,
        }
    }

    /// Augments the issuer's public key if required for the protocol.
    /// Returns None if the issuer's public key should be used verbatim.
    fn augment_public_key(&self, pk: &PublicKey) -> Option<PublicKey> {
        match self {
            TokenProtocol::Basic => None,
            TokenProtocol::PublicMetadata { metadata } => Some(augment_public_key(pk, metadata)),
        }
    }

    fn augment_private_key(&self, sk: SecretKey) -> SecretKey {
        match self {
            TokenProtocol::Basic => sk,
            TokenProtocol::PublicMetadata { metadata } => augment_private_key(&sk, metadata),
        }
    }

    fn prepare_message(&self, input_message: Vec<u8>) -> Vec<u8> {
        match self {
            TokenProtocol::Basic => input_message,
            TokenProtocol::PublicMetadata { metadata } => {
                encode_message_metadata(&input_message, metadata)
            }
        }
    }
}
