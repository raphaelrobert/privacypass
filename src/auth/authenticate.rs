use pest::Parser;
use pest_derive::Parser;
use sha2::{Digest, Sha256};
use thiserror::*;
use tls_codec::{Serialize, TlsByteVecU16};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::{ChallengeDigest, TokenType};

pub type RedemptionContext = [u8; 32];

/// A TokenChallenge, as defined in The Privacy Pass HTTP Authentication Scheme:
///
/// ```text
/// struct {
///     uint16_t token_type;
///     opaque issuer_name<1..2^16-1>;
///     opaque redemption_context<0..32>;
///     opaque origin_info<0..2^16-1>;
/// } TokenChallenge;
/// ```
#[derive(TlsSize, TlsDeserialize, TlsSerialize)]
pub struct TokenChallenge {
    token_type: TokenType,
    issuer_name: TlsByteVecU16,
    redemption_context: Option<RedemptionContext>,
    origin_info: TlsByteVecU16,
}

impl TokenChallenge {
    /// Creates a new TokenChallenge.
    pub fn new(
        token_type: TokenType,
        issuer_name: &str,
        redemption_context: Option<RedemptionContext>,
        origin_info: Vec<String>,
    ) -> Self {
        Self {
            token_type,
            issuer_name: issuer_name.as_bytes().into(),
            redemption_context,
            origin_info: origin_info.join(",").as_bytes().into(),
        }
    }

    /// Serializes the TokenChallenge.
    pub fn serialize(&self) -> Result<Vec<u8>, SerializationError> {
        self.tls_serialize_detached()
            .map_err(|_| SerializationError::InvalidTokenChallenge)
    }

    /// Serializes the TokenChallenge as a base64 encoded string.
    pub fn to_base64(&self) -> Result<String, SerializationError> {
        Ok(base64::encode(&self.serialize()?))
    }

    /// Serializes and hashes the TokenChallenge with SHA256.
    pub fn digest(&self) -> Result<ChallengeDigest, SerializationError> {
        Ok(Sha256::digest(&self.serialize()?).into())
    }
}

#[derive(Error, Debug)]
pub enum SerializationError {
    #[error("Invalid TokenChallenge")]
    InvalidTokenChallenge,
}

/// Builds a `WWW-Authenticate` header according to the following scheme:
///
/// `PrivateToken challenge=... token-key=... [max-age=...]`
pub fn build_www_authenticate_header(
    token_challenge: TokenChallenge,
    token_key: &[u8],
    max_age: Option<usize>,
) -> Result<String, BuildError> {
    let challenge_value = token_challenge
        .to_base64()
        .map_err(|_| BuildError::InvalidTokenChallenge)?;
    let token_key_value = base64::encode(token_key);
    let max_age_string = if let Some(max_age) = max_age {
        format!(", max-age={}", max_age)
    } else {
        "".to_string()
    };

    let value = format!(
        "PrivateToken challenge={}, token-key={}{}",
        challenge_value, token_key_value, max_age_string
    );
    Ok(value)
}

/// Building error for the `Authorization` header values
#[derive(Error, Debug)]
pub enum BuildError {
    #[error("Invalid TokenChallenge")]
    InvalidTokenChallenge,
}

/// Parses a `WWW-Authenticate` header according to the following scheme:
///
/// `PrivateToken challenge=... token-key=... [max-age=...]`
pub fn parse_www_authenticate_header(value: &str) -> Result<Vec<Challenge>, ParseError> {
    WwwAuthenticateParser::try_from_str(value)
}

/// Decoded challenge from a `WWW-Authenicate` header
#[derive(Debug, PartialEq)]
pub struct Challenge {
    challenge: String,
    token_key: Vec<u8>,
    max_age: Option<usize>,
}

/// Parsing error for the `WWW-Authenticate` header values
#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Invalid challenge")]
    InvalidChallenge,
    #[error("Invalid token key")]
    InvalidTokenKey,
    #[error("Invalid max age")]
    InvalidMaxAge,
    #[error("Invalid input string")]
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
    fn try_from_str(value: &str) -> Result<Vec<Challenge>, ParseError> {
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
                    challenge: challenge_param.to_owned(),
                    token_key: base64::decode(token_key_param)
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
    let token_key = "sample token key".as_bytes().to_vec();
    let token_challenge = TokenChallenge::new(
        TokenType::Private,
        "issuer",
        None,
        vec!["origin".to_string()],
    );
    let serialized_token_challenge = token_challenge.to_base64().unwrap();
    let max_age = 100;
    let value = build_www_authenticate_header(token_challenge, &token_key, Some(max_age)).unwrap();

    let expected_value = format!(
        "PrivateToken challenge={}, token-key={}, max-age={}",
        serialized_token_challenge,
        base64::encode(&token_key),
        max_age
    );
    assert_eq!(value, expected_value);
}

#[test]
fn parser_test() {
    let token_key1 = "sample token key 1".as_bytes().to_vec();
    let token_key2 = "sample token key 2".as_bytes().to_vec();

    let input = format!(
        "PrivateToken challenge=1abc, token-key={}, max-age=10, PrivateToken challenge=3ghi, token-key={}", base64::encode(&token_key1), base64::encode(&token_key2));

    let challenges = parse_www_authenticate_header(&input).unwrap();

    assert_eq!(
        challenges,
        vec![
            Challenge {
                challenge: "1abc".to_owned(),
                token_key: token_key1,
                max_age: Some(10),
            },
            Challenge {
                challenge: "3ghi".to_owned(),
                token_key: token_key2,
                max_age: None,
            }
        ]
    );
}

#[test]
fn builder_parser_test() {
    let token_key = "sample token key".as_bytes().to_vec();
    let token_challenge = TokenChallenge::new(
        TokenType::Private,
        "issuer",
        None,
        vec!["origin".to_string()],
    );
    let serialized_token_challenge = token_challenge.to_base64().unwrap();
    let max_age = 100;
    let value = build_www_authenticate_header(token_challenge, &token_key, Some(max_age)).unwrap();
    let challenges = parse_www_authenticate_header(&value).unwrap();

    assert_eq!(
        challenges,
        vec![Challenge {
            challenge: serialized_token_challenge,
            token_key,
            max_age: Some(max_age),
        }]
    );
}
