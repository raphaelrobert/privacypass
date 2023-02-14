//! This module contains the authentication logic for the challenge phase of the
//! protocol.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::{header::HeaderName, HeaderValue};
use pest::Parser;
use pest_derive::Parser;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tls_codec::{Serialize, TlsByteVecU16, Deserialize, TlsByteVecU8};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};


use crate::{ChallengeDigest, TokenType};

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
    #[must_use] pub fn new(
        token_type: TokenType,
        issuer_name: &str,
        redemption_context: Option<RedemptionContext>,
        origin_info: &[String],
    ) -> Self {
        Self {
            token_type,
            issuer_name: issuer_name.as_bytes().into(),
            redemption_context: redemption_context.map(|rc| rc.to_vec().into()).unwrap_or_default(),
            origin_info: origin_info.join(",").as_bytes().into(),
        }
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
        Self::tls_deserialize(&mut data)
            .map_err(|_| SerializationError::InvalidTokenChallenge)
    }

    /// Serializes the `TokenChallenge` as a base64 encoded string.
    /// 
    /// # Errors
    /// Returns an error if the `TokenChallenge` cannot be serialized.
    pub fn to_base64(&self) -> Result<String, SerializationError> {
        Ok(STANDARD.encode(self.serialize()?))
    }

    /// Deserializes a `TokenChallenge` from a base64 encoded string.
    /// 
    /// # Errors
    /// Returns an error if the `TokenChallenge` cannot be deserialized.
    pub fn from_base64(s: &str) -> Result<Self, SerializationError> {
        STANDARD.decode(s).map_err(|_| SerializationError::InvalidTokenChallenge)
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
    max_age: Option<usize>,
) -> Result<(HeaderName, HeaderValue), BuildError> {
    let challenge_value = token_challenge
        .to_base64()
        .map_err(|_| BuildError::InvalidTokenChallenge)?;
    let token_key_value = STANDARD.encode(token_key);
    let max_age_string = max_age.map_or_else(|| "".to_string(), |max_age| format!(", max-age={max_age}"));

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
    WwwAuthenticateParser::try_from_bytes(value.as_bytes())
}

/// Decoded challenge from a `WWW-Authenicate` header
#[derive(Debug, PartialEq, Eq)]
pub struct Challenge {
    challenge: TokenChallenge,
    token_key: Vec<u8>,
    max_age: Option<usize>,
}

impl Challenge {
    /// Returns the token challenge
    #[must_use] pub const fn token_challenge(&self) -> &TokenChallenge {
        &self.challenge
    }

    /// Returns the token key as bytes
    #[must_use] pub fn token_key(&self) -> &[u8] {
        &self.token_key
    }

    /// Returns the optional max-age
    #[must_use] pub const fn max_age(&self) -> Option<usize> {
        self.max_age
    }
}

/// Parsing error for the `WWW-Authenticate` header values
#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Invalid challenge")]
    /// Invalid challenge
    InvalidChallenge,
    #[error("Invalid token key")]
    /// Invalid token key
    InvalidTokenKey,
    #[error("Invalid max age")]
    /// Invalid max-age
    InvalidMaxAge,
    #[error("Invalid input string")]
    /// Invalid input string
    InvalidInput,
}

#[derive(Parser)]
#[grammar_inline = r#"
WHITESPACE = _{ " " }
name_char = { ASCII_ALPHANUMERIC | "-" }
base64_char = { ASCII_ALPHANUMERIC | "+" | "/" | "=" }
name = @{ name_char+ }
value = @{ base64_char* }
num_value = { ASCII_DIGIT+ }
property = { name ~ "=" ~ value }
challenge_param = { "challenge=" ~ value }
token_key_param = { "token-key=" ~ value }
max_age_param = { "max-age=" ~ num_value }
challenge = { "PrivateToken " ~ challenge_param ~ "," ~ token_key_param ~ ("," ~ max_age_param)? }
challenge_list = {
    SOI ~
     ((challenge ~ ",") | challenge)+ ~
    EOI
}
"#]
struct WwwAuthenticateParser {}

impl WwwAuthenticateParser {
    fn try_from_bytes(value: &[u8]) -> Result<Vec<Challenge>, ParseError> {
        let value = std::str::from_utf8(value).map_err(|_| ParseError::InvalidInput)?;
        let mut challenges = Vec::new();
        let challenge_list = Self::parse(Rule::challenge_list, value)
            .map_err(|_| ParseError::InvalidInput)?
            .next()
            .ok_or(ParseError::InvalidInput)?
            .into_inner();
        for challenge in challenge_list {
            let mut params = challenge.into_inner();

            if params.peek().is_some() {
                let challenge_param = params
                    .next()
                    .ok_or(ParseError::InvalidChallenge)?
                    .into_inner()
                    .next()
                    .ok_or(ParseError::InvalidChallenge)?
                    .as_str();
                let token_key_param = params
                    .next()
                    .ok_or(ParseError::InvalidTokenKey)?
                    .into_inner()
                    .next()
                    .ok_or(ParseError::InvalidTokenKey)?
                    .as_str();
                let max_age_param = match params.next() {
                    Some(max_age_param) => {
                        let max_age_param = max_age_param
                            .into_inner()
                            .next()
                            .ok_or(ParseError::InvalidMaxAge)?
                            .as_str();
                        Some(
                            max_age_param
                                .parse::<usize>()
                                .map_err(|_| ParseError::InvalidMaxAge)?,
                        )
                    }
                    None => None,
                };
                let challenge = Challenge {
                    challenge: TokenChallenge::from_base64(challenge_param)
                        .map_err(|_| ParseError::InvalidChallenge)?,
                    token_key: STANDARD.decode(token_key_param)
                        .map_err(|_| ParseError::InvalidTokenKey)?,
                    max_age: max_age_param,
                };
                challenges.push(challenge);
            }
        }
        Ok(challenges)
    }
}

#[test]
fn builder_test() {
    let token_key = b"sample token key".to_vec();
    let token_challenge = TokenChallenge::new(
        TokenType::Private,
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
        STANDARD.encode(&token_key),
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
        TokenType::Private,
        "issuer1",
        None,
        &["origin1".to_string()],
    );

    let challenge2 = TokenChallenge::new(
        TokenType::Private,
        "issuer2",
        None,
        &["origin2".to_string()],
    );

    let input = HeaderValue::from_str(&format!(
            "PrivateToken challenge={}, token-key={}, max-age=10, PrivateToken challenge={}, token-key={}", 
            challenge1.to_base64().unwrap(),
            STANDARD.encode(&token_key1), 
            challenge2.to_base64().unwrap(),
            STANDARD.encode(&token_key2)))
        .unwrap();

    let challenge_list = parse_www_authenticate_header(&input).unwrap();

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
    use voprf::{Ristretto255, Group};
    use crate::batched_tokens::server::{serialize_public_key, deserialize_public_key};

    let public_key = Ristretto255::base_elem();
    let token_key = serialize_public_key(public_key);
    let token_challenge = TokenChallenge::new(
        TokenType::Private,
        "issuer",
        None,
        &["origin".to_string()],
    );
    let max_age = 100;
    let (_header_name, header_value) =
        build_www_authenticate_header(&token_challenge, &token_key, Some(max_age)).unwrap();
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
