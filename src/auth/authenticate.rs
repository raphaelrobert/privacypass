//! This module contains the authentication logic for the challenge phase of the
//! protocol.

use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use http::{HeaderValue, header::HeaderName};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tls_codec::{Deserialize, Serialize, TlsByteVecU8, TlsByteVecU16};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

use nom::{
    IResult, Parser,
    bytes::complete::{tag, tag_no_case},
    character::complete::digit1,
    combinator::opt,
    multi::{many1, separated_list1},
};

use crate::{
    ChallengeDigest, TokenType,
    common::extensions::{ExtensionSet, Extensions},
};

use super::{comma_sep, key_name, maybe_unquote, opt_spaces, parse_u32, space, unquote};

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
    pub(crate) token_type: TokenType,
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
            self.redemption_context.as_slice().try_into().ok()
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
#[derive(PartialEq, Eq, Error, Debug)]
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

/// Builds a `WWW-Authenticate` header according to the following scheme
/// specified in
/// [`draft-ietf-privacypass-auth-scheme-extensions-03`](https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-auth-scheme-extensions-03):
///
/// `PrivateToken challenge="...", token-key="..." [, extension-set="..."] [, extensions="..."] [, max-age=...]`
///
/// # Errors
/// Returns an error if the `TokenChallenge` cannot be serialized.
pub fn build_www_authenticate_header_ext(
    token_challenge: &TokenChallenge,
    token_key: &[u8],
    max_age: Option<u32>,
    extension_set: Option<&ExtensionSet>,
    extensions: Option<&Extensions>,
) -> Result<(HeaderName, HeaderValue), BuildError> {
    let challenge_value = token_challenge
        .to_base64()
        .map_err(|_| BuildError::InvalidTokenChallenge)?;
    let token_key_value = URL_SAFE.encode(token_key);
    let max_age_string =
        max_age.map_or_else(|| "".to_string(), |max_age| format!(", max-age={max_age}"));

    let extension_set_kv = if let Some(extension_set) = extension_set {
        let extension_set_str = URL_SAFE.encode(
            extension_set
                .tls_serialize_detached()
                .map_err(|_| BuildError::InvalidExtensions)?,
        );
        format!(", extension-set=\"{extension_set_str}\"")
    } else {
        String::new()
    };

    let extension_kv = if let Some(extensions) = extensions {
        let ext_str = URL_SAFE.encode(
            extensions
                .tls_serialize_detached()
                .map_err(|_| BuildError::InvalidExtensions)?,
        );

        format!(", extensions=\"{ext_str}\"")
    } else {
        String::new()
    };

    let value = format!(
        "PrivateToken challenge=\"{challenge_value}\", token-key=\"{token_key_value}\"{extension_set_kv}{extension_kv}{max_age_string}"
    );
    let header_name = http::header::WWW_AUTHENTICATE;
    let header_value =
        HeaderValue::from_str(&value).map_err(|_| BuildError::InvalidTokenChallenge)?;
    Ok((header_name, header_value))
}

/// Building error for the `Authorization` header values
#[derive(PartialEq, Eq, Error, Debug)]
pub enum BuildError {
    #[error("Invalid TokenChallenge")]
    /// Invalid TokenChallenge
    InvalidTokenChallenge,
    #[error("Invalid extensions")]
    /// Invalid extensions
    InvalidExtensions,
}

/// Parses a `WWW-Authenticate` header according to the following scheme:
///
/// `PrivateToken challenge=... token-key=... [max-age=...]`
///
/// # Errors
/// Returns an error if the `WWW-Authenticate` header cannot be parsed.
pub fn parse_www_authenticate_header(value: &HeaderValue) -> Result<Vec<Challenge>, ParseError> {
    let s = value.to_str().map_err(|_| ParseError::InvalidInput)?;
    // in RFC 9577 section 2.2.2, it says the token field might be a quoted string, so when
    // parsing without extensions, we need to accept values that are not quoted as well.
    let (_, challenges) =
        parse_private_tokens(s, false).map_err(|_| ParseError::InvalidChallenge)?;

    Ok(challenges
        .into_iter()
        .map(|(challenge, _, _)| challenge)
        .collect())
}

/// Parses a `WWW-Authenticate` header according to the following scheme
/// specified in
/// [`draft-ietf-privacypass-auth-scheme-extensions-03`](https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-auth-scheme-extensions-03):
///
/// `PrivateToken challenge="...", token-key="...", extension-set="..." [, extensions="..."] [, max-age=...]`
///
/// # Errors
/// Returns an error if the `WWW-Authenticate` header cannot be parsed.
#[allow(clippy::type_complexity)]
pub fn parse_www_authenticate_header_ext(
    value: &HeaderValue,
) -> Result<Vec<(Challenge, Option<ExtensionSet>, Option<Extensions>)>, ParseError> {
    let s = value.to_str().map_err(|_| ParseError::InvalidInput)?;
    // In draft-ietf-privacypass-auth-scheme-extensions-03, it says token and extensions MUST be
    // enclosed in double-quotes. Thus, when parsing both tokens and extensions, we should
    // strictly accept only quoted values.
    let (_, challenges) =
        parse_private_tokens(s, true).map_err(|_| ParseError::InvalidChallenge)?;

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

fn parse_key_value(input: &str, strict_quotes: bool) -> IResult<&str, (&str, &str)> {
    let (input, _) = opt_spaces(input)?;
    let (input, key) = key_name(input)?;
    let (input, _) = opt_spaces(input)?;
    let (input, _) = tag("=")(input)?;
    let (input, _) = opt_spaces(input)?;
    let (input, value) = match key.to_lowercase().as_str() {
        "challenge" | "token-key" => {
            if strict_quotes {
                unquote(input)?
            } else {
                maybe_unquote(input)?
            }
        }
        "extension-set" | "extensions" => unquote(input)?,
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

fn parse_private_token(
    input: &str,
    strict_quotes: bool,
) -> IResult<&str, (Challenge, Option<ExtensionSet>, Option<Extensions>)> {
    let (input, _) = opt_spaces(input)?;
    let (input, _) = tag_no_case("PrivateToken")(input)?;
    let (input, _) = many1(space).parse(input)?;
    let (input, _) = opt(comma_sep).parse(input)?;
    let (input, key_values) =
        separated_list1(comma_sep, |i| parse_key_value(i, strict_quotes)).parse(input)?;

    let mut challenge = None;
    let mut token_key = None;
    let mut max_age = None;
    let mut extension_set = None;
    let mut extensions = None;

    for (key, value) in key_values {
        let err = nom::Err::Failure(nom::error::make_error(input, nom::error::ErrorKind::Tag));
        match key.to_lowercase().as_str() {
            "challenge" => challenge = Some(TokenChallenge::from_base64(value).map_err(|_| err)?),
            "token-key" => token_key = Some(URL_SAFE.decode(value).map_err(|_| err)?),
            "max-age" => {
                let parsed_max_age = parse_u32(value).map_err(|_| err)?;
                max_age = Some(parsed_max_age);
            }
            "extension-set" => {
                extension_set = Some(
                    ExtensionSet::tls_deserialize_exact(
                        URL_SAFE.decode(value).map_err(|_| err.clone())?,
                    )
                    .map_err(|_| err)?,
                )
            }
            "extensions" => {
                extensions = Some(
                    Extensions::tls_deserialize_exact(
                        URL_SAFE.decode(value).map_err(|_| err.clone())?,
                    )
                    .map_err(|_| err)?,
                )
            }
            _ => return Err(err),
        }
    }

    if let (Some(challenge), Some(token_key)) = (challenge, token_key) {
        Ok((
            input,
            (
                Challenge {
                    challenge,
                    token_key,
                    max_age,
                },
                extension_set,
                extensions,
            ),
        ))
    } else {
        Err(nom::Err::Failure(nom::error::make_error(
            input,
            nom::error::ErrorKind::Verify,
        )))
    }
}

#[allow(clippy::type_complexity)]
fn parse_private_tokens(
    input: &str,
    strict_quotes: bool,
) -> IResult<&str, Vec<(Challenge, Option<ExtensionSet>, Option<Extensions>)>> {
    let (input, _) = opt(comma_sep).parse(input)?;
    let (input, tokens) =
        separated_list1(comma_sep, |i| parse_private_token(i, strict_quotes)).parse(input)?;
    let (input, _) = opt(comma_sep).parse(input)?;
    let (input, _) = opt_spaces(input)?;
    Ok((input, tokens))
}

#[cfg(test)]
mod tests {
    use crate::{
        TokenType,
        auth::authenticate::{
            Challenge, TokenChallenge, build_www_authenticate_header,
            build_www_authenticate_header_ext, parse_private_tokens, parse_www_authenticate_header,
            parse_www_authenticate_header_ext,
        },
        common::extensions::{Extension, ExtensionEntry, ExtensionSet, ExtensionType, Extensions},
        common::private::{deserialize_public_key, serialize_public_key},
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE};
    use http::HeaderValue;
    use tls_codec::Serialize;
    use voprf::{Group, Ristretto255};

    #[test]
    fn builder_test() {
        let token_key = b"sample token key".to_vec();
        let token_challenge = TokenChallenge::new(
            TokenType::PrivateP384,
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
            TokenType::PrivateP384,
            "issuer1",
            None,
            &["origin1".to_string()],
        );

        let challenge2 = TokenChallenge::new(
            TokenType::PrivateP384,
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

        let (_, challenge_list) = parse_private_tokens(input.to_str().unwrap(), false).unwrap();
        let challenge_list: Vec<_> = challenge_list
            .into_iter()
            .map(|(challenge, _, _)| challenge)
            .collect();

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
        let public_key = Ristretto255::base_elem();
        let token_key = serialize_public_key::<Ristretto255>(public_key);
        let token_challenge = TokenChallenge::new(
            TokenType::PrivateP384,
            "issuer",
            None,
            &["origin".to_string()],
        );
        let max_age = 100u32;
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
        let deserialized_public_key =
            deserialize_public_key::<Ristretto255>(challenge.token_key()).unwrap();
        assert_eq!(deserialized_public_key, public_key);
    }

    #[test]
    fn builder_test_ext() {
        let token_key = b"sample token key".to_vec();
        let token_challenge = TokenChallenge::new(
            TokenType::PublicMetadata,
            "issuer",
            None,
            &["origin".to_string()],
        );
        let max_age = 100u32;

        let extension_set = ExtensionSet::new(vec![
            ExtensionEntry::new(true, ExtensionType(1)),
            ExtensionEntry::new(false, ExtensionType(2)),
        ]);
        let extensions = Extensions::new(vec![
            Extension::new(ExtensionType(1), b"hello".to_vec()).unwrap(),
            Extension::new(ExtensionType(2), b"world".to_vec()).unwrap(),
        ])
        .unwrap();

        let (header_name, header_value) = build_www_authenticate_header_ext(
            &token_challenge,
            &token_key,
            Some(max_age),
            Some(&extension_set),
            Some(&extensions),
        )
        .unwrap();

        let expected_value = format!(
            "PrivateToken challenge=\"{}\", token-key=\"{}\", extension-set=\"{}\", extensions=\"{}\", max-age={}",
            token_challenge.to_base64().unwrap(),
            URL_SAFE.encode(&token_key),
            URL_SAFE.encode(extension_set.tls_serialize_detached().unwrap()),
            URL_SAFE.encode(extensions.tls_serialize_detached().unwrap()),
            max_age
        );

        assert_eq!(header_name, http::header::WWW_AUTHENTICATE);
        assert_eq!(header_value.as_bytes(), expected_value.as_bytes());
    }

    #[test]
    fn parser_test_ext() {
        let token_key = b"sample token key".to_vec();
        let token_challenge = TokenChallenge::new(
            TokenType::PublicMetadata,
            "issuer",
            None,
            &["origin".to_string()],
        );

        let extension_set = ExtensionSet::new(vec![
            ExtensionEntry::new(true, ExtensionType(1)),
            ExtensionEntry::new(false, ExtensionType(2)),
        ]);
        let extensions = Extensions::new(vec![
            Extension::new(ExtensionType(1), b"hello world".to_vec()).unwrap(),
        ])
        .unwrap();

        let input = HeaderValue::from_str(&format!(
            "PrivateToken challenge=\"{}\", token-key=\"{}\", extension-set=\"{}\", extensions=\"{}\", max-age={}",
            token_challenge.to_base64().unwrap(),
            URL_SAFE.encode(&token_key),
            URL_SAFE.encode(extension_set.tls_serialize_detached().unwrap()),
            URL_SAFE.encode(extensions.tls_serialize_detached().unwrap()),
            42u32,
        ))
        .unwrap();

        let (_, challenge_list) = parse_private_tokens(input.to_str().unwrap(), true).unwrap();

        assert_eq!(
            challenge_list,
            vec![(
                Challenge {
                    challenge: token_challenge,
                    token_key,
                    max_age: Some(42),
                },
                Some(extension_set),
                Some(extensions),
            )]
        );
    }

    #[test]
    fn builder_parser_test_ext() {
        let token_key = b"sample token key".to_vec();
        let token_challenge = TokenChallenge::new(
            TokenType::PublicMetadata,
            "issuer",
            None,
            &["origin".to_string()],
        );
        let max_age = 100u32;

        let extension_set = ExtensionSet::new(vec![
            ExtensionEntry::new(true, ExtensionType(1)),
            ExtensionEntry::new(false, ExtensionType(2)),
        ]);
        let extensions = Extensions::new(vec![
            Extension::new(ExtensionType(1), b"hello".to_vec()).unwrap(),
            Extension::new(ExtensionType(2), b"world".to_vec()).unwrap(),
        ])
        .unwrap();

        let (_header_name, header_value) = build_www_authenticate_header_ext(
            &token_challenge,
            &token_key,
            Some(max_age),
            Some(&extension_set),
            Some(&extensions),
        )
        .unwrap();

        let parsed = parse_www_authenticate_header_ext(&header_value).unwrap();

        assert_eq!(
            parsed,
            vec![(
                Challenge {
                    challenge: token_challenge,
                    token_key,
                    max_age: Some(max_age),
                },
                Some(extension_set),
                Some(extensions),
            )]
        );
    }
}
