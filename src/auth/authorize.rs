//! This module contains the authorization logic for redemption phase of the
//! protocol.

use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use generic_array::{ArrayLength, GenericArray};
use http::{HeaderValue, header::HeaderName};
use nom::{
    IResult, Parser,
    bytes::complete::{tag, tag_no_case},
    combinator::opt,
    multi::{many1, separated_list1},
};
use std::io::Write;
use thiserror::Error;
use tls_codec::{Deserialize, Error, Serialize, Size};

use crate::{
    ChallengeDigest, Nonce, TokenKeyId, TokenType, auth::maybe_unquote,
    common::extensions::Extensions,
};

use super::{comma_sep, key_name, opt_spaces, space, unquote};

/// A Token as defined in The Privacy Pass HTTP Authentication Scheme:
///
/// ```text
/// struct {
///     uint16_t token_type = 0x0001
///     uint8_t nonce[32];
///     uint8_t challenge_digest[32];
///     uint8_t token_key_id[32];
///     uint8_t authenticator[Nk];
/// } Token;
/// ```

#[derive(Clone, Debug)]
pub struct Token<Nk: ArrayLength> {
    token_type: TokenType,
    nonce: Nonce,
    challenge_digest: ChallengeDigest,
    token_key_id: TokenKeyId,
    authenticator: GenericArray<u8, Nk>,
}

impl<Nk: ArrayLength> Size for Token<Nk> {
    fn tls_serialized_len(&self) -> usize {
        self.token_type.tls_serialized_len()
            + self.nonce.tls_serialized_len()
            + self.challenge_digest.tls_serialized_len()
            + self.token_key_id.tls_serialized_len()
            + Nk::to_usize()
    }
}

impl<Nk: ArrayLength> Serialize for Token<Nk> {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        Ok(self.token_type.tls_serialize(writer)?
            + self.nonce.tls_serialize(writer)?
            + self.challenge_digest.tls_serialize(writer)?
            + self.token_key_id.tls_serialize(writer)?
            + writer.write(&self.authenticator[..])?)
    }
}

impl<Nk: ArrayLength> Deserialize for Token<Nk> {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let token_type = TokenType::tls_deserialize(bytes)?;
        let nonce = Nonce::tls_deserialize(bytes)?;
        let challenge_digest = ChallengeDigest::tls_deserialize(bytes)?;
        let token_key_id = TokenKeyId::tls_deserialize(bytes)?;
        let mut authenticator = vec![0u8; Nk::to_usize()];
        let len = bytes.read(authenticator.as_mut_slice())?;
        if len != Nk::to_usize() {
            return Err(Error::InvalidVectorLength);
        }
        Ok(Self {
            token_type,
            nonce,
            challenge_digest,
            token_key_id,
            authenticator: GenericArray::from_slice(&authenticator).clone(),
        })
    }
}

impl<Nk: ArrayLength> Token<Nk> {
    /// Creates a new Token.
    pub const fn new(
        token_type: TokenType,
        nonce: Nonce,
        challenge_digest: ChallengeDigest,
        token_key_id: TokenKeyId,
        authenticator: GenericArray<u8, Nk>,
    ) -> Self {
        Self {
            token_type,
            nonce,
            challenge_digest,
            token_key_id,
            authenticator,
        }
    }

    /// Returns the token type.
    pub const fn token_type(&self) -> TokenType {
        self.token_type
    }

    /// Returns the nonce.
    pub const fn nonce(&self) -> Nonce {
        self.nonce
    }

    /// Returns the challenge digest.
    pub const fn challenge_digest(&self) -> &ChallengeDigest {
        &self.challenge_digest
    }

    /// Returns the token key ID.
    pub const fn token_key_id(&self) -> &TokenKeyId {
        &self.token_key_id
    }

    /// Returns the authenticator.
    pub fn authenticator(&self) -> &[u8] {
        self.authenticator.as_ref()
    }
}

/// Builds a `Authorize` header according to the following scheme:
///
/// `PrivateToken token=...`
///
/// # Errors
/// Returns an error if the token is not valid.
pub fn build_authorization_header<Nk: ArrayLength>(
    token: &Token<Nk>,
) -> Result<(HeaderName, HeaderValue), BuildError> {
    let value = format!(
        "PrivateToken token={}",
        URL_SAFE.encode(
            token
                .tls_serialize_detached()
                .map_err(|_| BuildError::InvalidToken)?
        ),
    );
    let header_name = http::header::AUTHORIZATION;
    let header_value = HeaderValue::from_str(&value).map_err(|_| BuildError::InvalidToken)?;
    Ok((header_name, header_value))
}

/// Builds an `Authorize` header according to the following scheme,
/// specified in
/// [`draft-ietf-privacypass-auth-scheme-extensions-03`](https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-auth-scheme-extensions-03):
///
/// PrivateToken token="abc...", extensions="def..."
///
/// # Errors
/// Returns an error if the token or extensions are invalid.
pub fn build_authorization_header_ext<Nk: ArrayLength>(
    token: &Token<Nk>,
    extensions: &Extensions,
) -> Result<(HeaderName, HeaderValue), BuildError> {
    let value = format!(
        // format specified by draft-ietf-privacypass-auth-scheme-extensions-03
        // draft requires that the parameters must be enclosed in double quotes
        "PrivateToken token=\"{}\", extensions=\"{}\"",
        URL_SAFE.encode(
            token
                .tls_serialize_detached()
                .map_err(|_| BuildError::InvalidToken)?
        ),
        URL_SAFE.encode(
            extensions
                .tls_serialize_detached()
                .map_err(|_| BuildError::InvalidExtensions)?
        )
    );

    let header_name = http::header::AUTHORIZATION;
    let header_value = HeaderValue::from_str(&value).map_err(|_| BuildError::InvalidToken)?;

    Ok((header_name, header_value))
}

/// Building error for the `Authorization` header values
#[derive(PartialEq, Eq, Error, Debug)]
pub enum BuildError {
    #[error("Invalid token")]
    /// Invalid token
    InvalidToken,
    #[error("Invalid extensions")]
    /// Invalid extensions
    InvalidExtensions,
}

/// Parses an `Authorization` header according to the following scheme:
///
/// `PrivateToken token=...`
///
/// # Errors
/// Returns an error if the header value is not valid.
pub fn parse_authorization_header<Nk: ArrayLength>(
    value: &HeaderValue,
) -> Result<Token<Nk>, ParseError> {
    let s = value.to_str().map_err(|_| ParseError::InvalidInput)?;

    parse_authorization_str(s)
}

/// Parses an `Authorization` string according to the following scheme:
///
/// `PrivateToken token=...`
///
/// # Errors
/// Returns an error if the header value is not valid.
pub fn parse_authorization_str<Nk: ArrayLength>(s: &str) -> Result<Token<Nk>, ParseError> {
    // in RFC 9577 section 2.2.2, it says the token field might be a quoted string, so when
    // parsing just a token, we need to accept values that are not quoted as well.
    let tokens = parse_header_value(s, false)?;

    tokens
        .into_iter()
        .next()
        .ok_or(ParseError::InvalidInput)
        .map(|(token, _)| token)
}

/// Parses an `Authorization` header according to the following scheme,
/// specified in
/// [`draft-ietf-privacypass-auth-scheme-extensions-03`](https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-auth-scheme-extensions-03):
///
/// `PrivateToken token="..." [, extensions="..."]`
///
/// # Errors
/// Returns an error if the header value is not valid.
pub fn parse_authorization_header_ext<Nk: ArrayLength>(
    value: &HeaderValue,
) -> Result<(Token<Nk>, Option<Extensions>), ParseError> {
    let s = value.to_str().map_err(|_| ParseError::InvalidInput)?;

    parse_authorization_str_ext(s)
}

/// Parses an `Authorization` string according to the following scheme,
/// specified in
/// [`draft-ietf-privacypass-auth-scheme-extensions-03`](https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-auth-scheme-extensions-03):
///
/// `PrivateToken token="..." [, extensions="..."]`
///
/// # Errors
/// Returns an error if the header value is not valid.
pub fn parse_authorization_str_ext<Nk: ArrayLength>(
    s: &str,
) -> Result<(Token<Nk>, Option<Extensions>), ParseError> {
    // In draft-ietf-privacypass-auth-scheme-extensions-03, it says token and extensions MUST be
    // enclosed in double-quotes. Thus, when parsing both tokens and extensions, we should
    // strictly accept only quoted values.
    let tokens = parse_header_value(s, true)?;

    tokens.into_iter().next().ok_or(ParseError::InvalidInput)
}

/// Parsing error for the `WWW-Authenticate` header values
#[derive(PartialEq, Eq, Error, Debug)]
pub enum ParseError {
    #[error("Invalid token")]
    /// Invalid token
    InvalidToken,
    #[error("Invalid input string")]
    /// Invalid input string
    InvalidInput,
    #[error("Invalid extensions")]
    /// Invalid extensions
    InvalidExtensions,
}

fn parse_key_value(input: &str, strict_quotes: bool) -> IResult<&str, (&str, &str)> {
    let (input, _) = opt_spaces(input)?;
    let (input, key) = key_name(input)?;
    let (input, _) = opt_spaces(input)?;
    let (input, _) = tag("=").parse(input)?;
    let (input, _) = opt_spaces(input)?;
    let (input, value) = match key.to_lowercase().as_str() {
        // see comments in parse_authorization_str and parse_authorization_str_ext
        "token" => {
            if strict_quotes {
                unquote(input)?
            } else {
                maybe_unquote(input)?
            }
        }
        "extensions" => unquote(input)?,
        _ => {
            return Err(nom::Err::Failure(nom::error::make_error(
                input,
                nom::error::ErrorKind::Tag,
            )));
        }
    };
    Ok((input, (key, value)))
}

fn parse_private_token(input: &str, strict_quotes: bool) -> IResult<&str, (&str, Option<&str>)> {
    let (input, _) = opt_spaces(input)?;
    let (input, _) = tag_no_case("PrivateToken").parse(input)?;
    let (input, _) = many1(space).parse(input)?;
    let (input, _) = opt(comma_sep).parse(input)?;
    let (input, key_values) =
        separated_list1(comma_sep, |i| parse_key_value(i, strict_quotes)).parse(input)?;

    let mut token = None;
    let mut extensions = None;
    let err = nom::Err::Failure(nom::error::make_error(input, nom::error::ErrorKind::Tag));

    for (key, value) in key_values {
        match key.to_lowercase().as_str() {
            "token" => {
                if token.is_some() {
                    return Err(err);
                }
                token = Some(value)
            }
            "extensions" => {
                if extensions.is_some() {
                    return Err(err);
                }

                extensions = Some(value);
            }
            _ => return Err(err),
        }
    }
    let token = token.ok_or(err)?;

    Ok((input, (token, extensions)))
}

fn parse_private_tokens(
    input: &str,
    strict_quotes: bool,
) -> IResult<&str, Vec<(&str, Option<&str>)>> {
    let (input, _) = opt(comma_sep).parse(input)?;
    let (input, tokens) =
        separated_list1(comma_sep, |i| parse_private_token(i, strict_quotes)).parse(input)?;
    let (input, _) = opt(comma_sep).parse(input)?;
    let (input, _) = opt_spaces(input)?;
    Ok((input, tokens))
}

#[allow(clippy::type_complexity)]
fn parse_header_value<Nk: ArrayLength>(
    input: &str,
    strict_quotes: bool,
) -> Result<Vec<(Token<Nk>, Option<Extensions>)>, ParseError> {
    let (output, tokens) =
        parse_private_tokens(input, strict_quotes).map_err(|_| ParseError::InvalidInput)?;
    if !output.is_empty() {
        return Err(ParseError::InvalidInput);
    }
    let tokens = tokens
        .into_iter()
        .map(|(token_value, extensions_value)| {
            let ext = extensions_value
                .map(|x| {
                    let decoded = URL_SAFE
                        .decode(x)
                        .map_err(|_| ParseError::InvalidExtensions)?;
                    Extensions::tls_deserialize_exact(decoded.as_slice())
                        .map_err(|_| ParseError::InvalidExtensions)
                })
                .transpose()?;

            let token = Token::tls_deserialize_exact(
                URL_SAFE
                    .decode(token_value)
                    .map_err(|_| ParseError::InvalidToken)?
                    .as_slice(),
            )
            .map_err(|_| ParseError::InvalidToken)?;

            Ok((token, ext))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use crate::TokenType;
    use crate::auth::authorize::{
        Token, build_authorization_header, build_authorization_header_ext,
        parse_authorization_header, parse_authorization_header_ext,
    };
    use crate::common::extensions::{Extension, ExtensionType, Extensions};
    use generic_array::GenericArray;
    use generic_array::typenum::U32;

    #[test]
    fn builder_parser_test() {
        let nonce = [1u8; 32];
        let challenge_digest = [2u8; 32];
        let token_key_id = [3u8; 32];
        let authenticator = [4u8; 32];
        let token = Token::<U32>::new(
            TokenType::PrivateP384,
            nonce,
            challenge_digest,
            token_key_id,
            *GenericArray::from_slice(&authenticator),
        );

        let (header_name, header_value) = build_authorization_header(&token).unwrap();

        assert_eq!(header_name, http::header::AUTHORIZATION);

        let token = parse_authorization_header::<U32>(&header_value).unwrap();
        assert_eq!(token.token_type(), TokenType::PrivateP384);
        assert_eq!(token.nonce(), nonce);
        assert_eq!(token.challenge_digest(), &challenge_digest);
        assert_eq!(token.token_key_id(), &token_key_id);
        assert_eq!(token.authenticator(), &authenticator);
    }

    #[test]
    fn builder_parser_extensions_test() {
        let nonce = [1u8; 32];
        let challenge_digest = [2u8; 32];
        let token_key_id = [3u8; 32];
        let authenticator = [4u8; 32];
        let token = Token::<U32>::new(
            TokenType::PublicMetadata,
            nonce,
            challenge_digest,
            token_key_id,
            *GenericArray::from_slice(&authenticator),
        );

        let extension = Extension::new(ExtensionType(5), b"hello world".to_vec()).unwrap();
        let extensions = Extensions::new(vec![extension]).unwrap();
        let (header_name, header_value) =
            build_authorization_header_ext(&token, &extensions).unwrap();

        assert_eq!(header_name, http::header::AUTHORIZATION);

        let (token, maybe_extensions) =
            parse_authorization_header_ext::<U32>(&header_value).unwrap();
        assert_eq!(token.token_type(), TokenType::PublicMetadata);
        assert_eq!(token.nonce(), nonce);
        assert_eq!(token.challenge_digest(), &challenge_digest);
        assert_eq!(token.token_key_id(), &token_key_id);
        assert_eq!(token.authenticator(), &authenticator);
        assert_eq!(maybe_extensions, Some(extensions));
    }

    struct Vector {
        nonce: [u8; 32],
        challenge_digest: [u8; 32],
        token_key_id: [u8; 32],
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        let mut output = vec![];
        let chars: Vec<char> = s.chars().collect();

        for pair in chars.chunks(2) {
            let string_pair: String = pair.iter().collect();
            output.push(u8::from_str_radix(&string_pair, 16).unwrap());
        }

        output
    }

    fn hex32(s: &str) -> [u8; 32] {
        hex_to_bytes(s).try_into().unwrap()
    }

    #[test]
    fn builder_parser_extensions_test_cross_compat() {
        // test vectors taken from
        // https://github.com/cloudflare/privacypass-ts/blob/main/test/test_data/auth_scheme_token_with_extensions_v1.json
        // challenge digests were extracted from the token_authenticator_input field, located after
        // 2-byte token input and 32-byte nonce
        let vectors = [
            Vector {
                nonce: hex32("e01978182c469e5e026d66558ee186568614f235e41ef7e2378e6f202688abab"),
                challenge_digest: hex32(
                    "d95573d45e84e65d5ce4adaff401040b823a5586c30855580bff3ea0118f8192",
                ),
                token_key_id: hex32(
                    "ca572f8982a9ca248a3056186322d93ca147266121ddeb5632c07f1f71cd2708",
                ),
            },
            Vector {
                nonce: hex32("e01978182c469e5e026d66558ee186568614f235e41ef7e2378e6f202688abab"),
                challenge_digest: hex32(
                    "0021e3fccff3e175dabdef586fafdbb26fc0a869ee29d0229b592729fa6b1289",
                ),
                token_key_id: hex32(
                    "ca572f8982a9ca248a3056186322d93ca147266121ddeb5632c07f1f71cd2708",
                ),
            },
            Vector {
                nonce: hex32("e01978182c469e5e026d66558ee186568614f235e41ef7e2378e6f202688abab"),
                challenge_digest: hex32(
                    "e67c893c237722726064008792670a0368dbe8fcfd47c8233613bee3e1ee52ff",
                ),
                token_key_id: hex32(
                    "ca572f8982a9ca248a3056186322d93ca147266121ddeb5632c07f1f71cd2708",
                ),
            },
            Vector {
                nonce: hex32("e01978182c469e5e026d66558ee186568614f235e41ef7e2378e6f202688abab"),
                challenge_digest: hex32(
                    "69a780715896548c5eecaee2be452eac6bb001078a057993f665c653133b7ffc",
                ),
                token_key_id: hex32(
                    "ca572f8982a9ca248a3056186322d93ca147266121ddeb5632c07f1f71cd2708",
                ),
            },
            Vector {
                nonce: hex32("e01978182c469e5e026d66558ee186568614f235e41ef7e2378e6f202688abab"),
                challenge_digest: hex32(
                    "6d3d849f2508b23721cedafbbff8183c1d7f2ed2c586f3641b8131f5ed719ebf",
                ),
                token_key_id: hex32(
                    "ca572f8982a9ca248a3056186322d93ca147266121ddeb5632c07f1f71cd2708",
                ),
            },
        ];

        // all vectors use extension(0x0000, uint8[01, 02, 03])
        let extension = Extension::new(ExtensionType(0), vec![1, 2, 3]).unwrap();
        let extensions = Extensions::new(vec![extension]).unwrap();

        for vector in &vectors {
            let token = Token::<U32>::new(
                TokenType::PublicMetadata,
                vector.nonce,
                vector.challenge_digest,
                vector.token_key_id,
                *GenericArray::from_slice(&[0u8; 32]),
            );

            let (header_name, header_value) =
                build_authorization_header_ext(&token, &extensions).unwrap();

            assert_eq!(header_name, http::header::AUTHORIZATION);

            let (token, maybe_extensions) =
                parse_authorization_header_ext::<U32>(&header_value).unwrap();
            assert_eq!(token.token_type(), TokenType::PublicMetadata);
            assert_eq!(token.nonce(), vector.nonce);
            assert_eq!(token.challenge_digest(), &vector.challenge_digest);
            assert_eq!(token.token_key_id(), &vector.token_key_id);
            assert_eq!(maybe_extensions, Some(extensions.clone()));
        }
    }
}
