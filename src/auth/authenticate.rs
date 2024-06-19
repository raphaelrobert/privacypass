//! This module contains the authentication logic for the challenge phase of the
//! protocol.

use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use http::{header::HeaderName, HeaderValue};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tls_codec::{Deserialize, Serialize, TlsByteVecU16, TlsByteVecU8};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

use nom::{
    bytes::complete::{tag, tag_no_case},
    character::complete::digit1,
    multi::{many1, separated_list1},
    IResult,
};

use crate::{ChallengeDigest, TokenType};

use super::{base64_char, key_name, opt_spaces, parse_u32, space};

/// Redemption context filed of a ``TokenChallenge
pub type RedemptionContext = [u8; 32];

/// A `TokenChallenge`, as defined in The Privacy Pass HTTP Authentication Scheme:
///
/// ```text
/// struct {
///     uint16_t token_type;
///     opaque issuer_name<1..2^16-1>;
///     opaque redemption_context<0..32>;
///     opaque origin_info<0..2^16-1>;
/// } TokenChallenge;
/// ```
#[derive(Clone, Debug, PartialEq, Eq, TlsSize, TlsDeserialize, TlsSerialize)]
pub struct TokenChallenge {
    token_type: TokenType,
    issuer_name: TlsByteVecU16,
    redemption_context: TlsByteVecU8,
    origin_info: TlsByteVecU16,
}

impl TokenChallenge {
    /// Creates a new `TokenChallenge`.
    #[must_use]
    pub fn new(
        token_type: TokenType,
        issuer_name: &str,
        redemption_context: Option<RedemptionContext>,
        origin_info: &[String],
    ) -> Self {
        Self {
            token_type,
            issuer_name: issuer_name.as_bytes().into(),
            redemption_context: redemption_context
                .map(|rc| rc.to_vec().into())
                .unwrap_or_default(),
            origin_info: origin_info.join(",").as_bytes().into(),
        }
    }

    /// Returns the token type.
    #[must_use]
    pub const fn token_type(&self) -> TokenType {
        self.token_type
    }

    /// Returns the issuer name.
    #[must_use]
    pub fn issuer_name(&self) -> String {
        String::from_utf8_lossy(self.issuer_name.as_slice()).to_string()
    }

    /// Returns the redemption context.
    #[must_use]
    pub fn redemption_context(&self) -> Option<RedemptionContext> {
        if self.redemption_context.is_empty() {
            None
        } else {
            Some(self.redemption_context.as_slice().try_into().unwrap())
        }
    }

    /// Returns the origin info.
    #[must_use]
    pub fn origin_info(&self) -> Vec<String> {
        String::from_utf8_lossy(self.origin_info.as_slice())
            .split(',')
            .map(|s| s.to_string())
            .collect()
    }

    /// Serializes the `TokenChallenge`.
    ///
    /// # Errors
    /// Returns an error if the `TokenChallenge` cannot be serialized.
    pub fn serialize(&self) -> Result<Vec<u8>, SerializationError> {
        self.tls_serialize_detached()
            .map_err(|_| SerializationError::InvalidTokenChallenge)
    }

    /// Deserializes the `TokenChallenge`.
    ///
    /// # Errors
    /// Returns an error if the `TokenChallenge` cannot be deserialized.
    pub fn deserialize(mut data: &[u8]) -> Result<Self, SerializationError> {
        Self::tls_deserialize(&mut data).map_err(|_| SerializationError::InvalidTokenChallenge)
    }

    /// Serializes the `TokenChallenge` as a base64 encoded string.
    ///
    /// # Errors
    /// Returns an error if the `TokenChallenge` cannot be serialized.
    pub fn to_base64(&self) -> Result<String, SerializationError> {
        Ok(URL_SAFE.encode(self.serialize()?))
    }

    /// Deserializes a `TokenChallenge` from a base64 encoded string.
    ///
    /// # Errors
    /// Returns an error if the `TokenChallenge` cannot be deserialized.
    pub fn from_base64(s: &str) -> Result<Self, SerializationError> {
        URL_SAFE
            .decode(s)
            .map_err(|_| SerializationError::InvalidTokenChallenge)
            .and_then(|data| Self::deserialize(&data))
    }

    /// Serializes and hashes the `TokenChallenge` with SHA256.
    ///
    /// # Errors
    /// Returns an error if the `TokenChallenge` cannot be serialized.
    pub fn digest(&self) -> Result<ChallengeDigest, SerializationError> {
        Ok(Sha256::digest(self.serialize()?).into())
    }
}

/// An error that occurred during serialization or deserialization.
#[derive(Error, Debug)]
pub enum SerializationError {
    #[error("Invalid TokenChallenge")]
    /// Invalid TokenChallenge
    InvalidTokenChallenge,
    #[error("Invalid token key")]
    /// Invalid token key
    InvalidTokenKey,
}

/// Builds a `WWW-Authenticate` header according to the following scheme:
///
/// `PrivateToken challenge=... token-key=... [max-age=...]`
///
/// # Errors
/// Returns an error if the `TokenChallenge` cannot be serialized.
pub fn build_www_authenticate_header(
    token_challenge: &TokenChallenge,
    token_key: &[u8],
    max_age: Option<u32>,
) -> Result<(HeaderName, HeaderValue), BuildError> {
    let challenge_value = token_challenge
        .to_base64()
        .map_err(|_| BuildError::InvalidTokenChallenge)?;
    let token_key_value = URL_SAFE.encode(token_key);
    let max_age_string =
        max_age.map_or_else(|| "".to_string(), |max_age| format!(", max-age={max_age}"));

    let value = format!(
        "PrivateToken challenge={challenge_value}, token-key={token_key_value}{max_age_string}"
    );
    let header_name = http::header::WWW_AUTHENTICATE;
    let header_value =
        HeaderValue::from_str(&value).map_err(|_| BuildError::InvalidTokenChallenge)?;
    Ok((header_name, header_value))
}

/// Building error for the `Authorization` header values
#[derive(Error, Debug)]
pub enum BuildError {
    #[error("Invalid TokenChallenge")]
    /// Invalid TokenChallenge
    InvalidTokenChallenge,
}

/// Parses a `WWW-Authenticate` header according to the following scheme:
///
/// `PrivateToken challenge=... token-key=... [max-age=...]`
///
/// # Errors
/// Returns an error if the `WWW-Authenticate` header cannot be parsed.
pub fn parse_www_authenticate_header(value: &HeaderValue) -> Result<Vec<Challenge>, ParseError> {
    let s = value.to_str().map_err(|_| ParseError::InvalidInput)?;
    let (_, challenges) = parse_private_tokens(s).map_err(|_| ParseError::InvalidChallenge)?;

    Ok(challenges)
}

/// Decoded challenge from a `WWW-Authenicate` header
#[derive(Debug, PartialEq, Eq)]
pub struct Challenge {
    challenge: TokenChallenge,
    token_key: Vec<u8>,
    max_age: Option<u32>,
}

impl Challenge {
    /// Returns the token challenge
    #[must_use]
    pub const fn token_challenge(&self) -> &TokenChallenge {
        &self.challenge
    }

    /// Returns the token key as bytes
    #[must_use]
    pub fn token_key(&self) -> &[u8] {
        &self.token_key
    }

    /// Returns the optional max-age
    #[must_use]
    pub const fn max_age(&self) -> Option<u32> {
        self.max_age
    }
}

/// Parsing error for the `WWW-Authenticate` header values
#[derive(Error, Debug)]
pub enum ParseError {
    /// Invalid challenge
    #[error("Invalid challenge")]
    InvalidChallenge,
    /// Invalid input string
    #[error("Invalid token key")]
    InvalidInput,
}

fn parse_key_value(input: &str) -> IResult<&str, (&str, &str)> {
    let (input, _) = opt_spaces(input)?;
    let (input, key) = key_name(input)?;
    let (input, _) = opt_spaces(input)?;
    let (input, _) = tag("=")(input)?;
    let (input, _) = opt_spaces(input)?;
    let (input, value) = match key.to_lowercase().as_str() {
        "challenge" | "token-key" => base64_char(input)?,
        "max-age" => digit1(input)?,
        _ => {
            return Err(nom::Err::Failure(nom::error::make_error(
                input,
                nom::error::ErrorKind::Tag,
            )));
        }
    };
    Ok((input, (key, value)))
}

fn parse_private_token(input: &str) -> IResult<&str, Challenge> {
    let (input, _) = opt_spaces(input)?;
    let (input, _) = tag_no_case("PrivateToken")(input)?;
    let (input, _) = many1(space)(input)?;
    let (input, key_values) = separated_list1(tag(","), parse_key_value)(input)?;

    let mut challenge = None;
    let mut token_key = None;
    let mut max_age = None;

    for (key, value) in key_values {
        let err = nom::Err::Failure(nom::error::make_error(input, nom::error::ErrorKind::Tag));
        match key.to_lowercase().as_str() {
            "challenge" => challenge = Some(TokenChallenge::from_base64(value).map_err(|_| err)?),
            "token-key" => token_key = Some(URL_SAFE.decode(value).map_err(|_| err)?),
            "max-age" => {
                let parsed_max_age = parse_u32(value).map_err(|_| err)?;
                max_age = Some(parsed_max_age);
            }
            _ => return Err(err),
        }
    }

    if let (Some(challenge), Some(token_key)) = (challenge, token_key) {
        Ok((
            input,
            Challenge {
                challenge,
                token_key,
                max_age,
            },
        ))
    } else {
        Err(nom::Err::Failure(nom::error::make_error(
            input,
            nom::error::ErrorKind::Verify,
        )))
    }
}

fn parse_private_tokens(input: &str) -> IResult<&str, Vec<Challenge>> {
    separated_list1(tag(","), parse_private_token)(input)
}

#[test]
fn builder_test() {
    let token_key = b"sample token key".to_vec();
    let token_challenge = TokenChallenge::new(
        TokenType::PrivateToken,
        "issuer",
        None,
        &["origin".to_string()],
    );
    let serialized_token_challenge = token_challenge.to_base64().unwrap();
    let max_age = 100;

    let (header_name, header_value) =
        build_www_authenticate_header(&token_challenge, &token_key, Some(max_age)).unwrap();

    let expected_value = format!(
        "PrivateToken challenge={}, token-key={}, max-age={}",
        serialized_token_challenge,
        URL_SAFE.encode(&token_key),
        max_age
    );
    assert_eq!(header_name, http::header::WWW_AUTHENTICATE);
    assert_eq!(header_value.as_bytes(), expected_value.as_bytes());
}

#[test]
fn parser_test() {
    let token_key1 = b"sample token key 1".to_vec();
    let token_key2 = b"sample token key 2".to_vec();

    let challenge1 = TokenChallenge::new(
        TokenType::PrivateToken,
        "issuer1",
        None,
        &["origin1".to_string()],
    );

    let challenge2 = TokenChallenge::new(
        TokenType::PrivateToken,
        "issuer2",
        None,
        &["origin2".to_string()],
    );

    let input = HeaderValue::from_str(&format!(
            "PrivateToken challenge={}, token-key={}, max-age=10, PrivateToken challenge={}, token-key={}", 
            challenge1.to_base64().unwrap(),
            URL_SAFE.encode(&token_key1),
            challenge2.to_base64().unwrap(),
            URL_SAFE.encode(&token_key2)))
        .unwrap();

    let (_, challenge_list) = parse_private_tokens(input.to_str().unwrap()).unwrap();

    assert_eq!(
        challenge_list,
        vec![
            Challenge {
                challenge: challenge1,
                token_key: token_key1,
                max_age: Some(10),
            },
            Challenge {
                challenge: challenge2,
                token_key: token_key2,
                max_age: None,
            }
        ]
    );
}

#[test]
fn builder_parser_test() {
    use crate::batched_tokens_ristretto255::server::{
        deserialize_public_key, serialize_public_key,
    };
    use voprf::{Group, Ristretto255};

    let public_key = Ristretto255::base_elem();
    let token_key = serialize_public_key(public_key);
    let token_challenge = TokenChallenge::new(
        TokenType::PrivateToken,
        "issuer",
        None,
        &["origin".to_string()],
    );
    let max_age = 100u32;
    let (_header_name, header_value) =
        build_www_authenticate_header(&token_challenge, &token_key, Some(max_age)).unwrap();

    println!("header_value: {:?}", header_value);

    let challenges = parse_www_authenticate_header(&header_value).unwrap();

    assert_eq!(
        challenges,
        vec![Challenge {
            challenge: token_challenge,
            token_key,
            max_age: Some(max_age),
        }]
    );

    assert_eq!(challenges.len(), 1);
    let challenge = &challenges[0];
    let deserialized_public_key = deserialize_public_key(challenge.token_key()).unwrap();
    assert_eq!(deserialized_public_key, public_key);
}
