//! This module contains the authorization logic for redemption phase of the
//! protocol.

use base64::{
    Engine as _, alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig, general_purpose::URL_SAFE},
};
use generic_array::{ArrayLength, GenericArray};
use http::{HeaderValue, header::HeaderName};
use nom::{
    IResult, Parser,
    branch::alt,
    bytes::complete::{tag, tag_no_case},
    multi::{many1, separated_list1},
};
use std::io::Write;
use thiserror::Error;
use tls_codec::{Deserialize, Error, Serialize, Size};

use crate::{ChallengeDigest, Nonce, TokenKeyId, TokenType, common::extensions::Extensions};

use super::{key_name, opt_spaces, space, unquote};

// Previous versions of the Token Extensions draft (`draft-ietf-privacypass-auth-scheme-extensions`)
// didn't specify whether the token should be encoded with padding, leading some implementations to
// always encode without padding. Thus, we need to decode extensions with this engine in order to
// support those implementations.
//
// However, the latest version states that "the base64url value MUST include padding", so when
// generating the header in `build_authorization_header_ext`, URL_SAFE should be used instead of
// this engine.
const URL_SAFE_INDIFFERENT: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

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

/// Builds an `Authorize` header according to the following scheme:
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
        // format specified by draft-ietf-privacypass-auth-scheme-extensions
        // draft requires that the parameters must be enclosed in double quotes
        "PrivateToken token=\"{}\", extensions=\"{}\"",
        URL_SAFE.encode(
            token
                .tls_serialize_detached()
                .map_err(|_| BuildError::InvalidToken)?
        ),
        // See comment above URL_SAFE_INDIFFERENT
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
    let tokens = parse_header_value(s)?;
    let token = tokens[0].0.clone();
    Ok(token)
}

/// Parses an `Authorization` header according to the following scheme:
///
/// `PrivateToken token=... [, extensions=...]`
///
/// # Errors
/// Returns an error if the header value is not valid.
pub fn parse_authorization_header_ext<Nk: ArrayLength>(
    value: &HeaderValue,
) -> Result<(Token<Nk>, Option<Extensions>), ParseError> {
    let s = value.to_str().map_err(|_| ParseError::InvalidInput)?;
    let mut tokens = parse_header_value(s)?;
    Ok(tokens.pop().unwrap())
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

fn parse_key_value(input: &str) -> IResult<&str, (&str, &str)> {
    let (input, _) = opt_spaces(input)?;
    let (input, key) = key_name(input)?;
    let (input, _) = opt_spaces(input)?;
    let (input, _) = tag("=").parse(input)?;
    let (input, _) = opt_spaces(input)?;
    let (input, value) = match key.to_lowercase().as_str() {
        "token" | "extensions" => unquote(input)?,
        _ => {
            return Err(nom::Err::Failure(nom::error::make_error(
                input,
                nom::error::ErrorKind::Tag,
            )));
        }
    };
    Ok((input, (key, value)))
}

fn parse_private_token(input: &str) -> IResult<&str, (&str, Option<&str>)> {
    let (input, _) = opt_spaces(input)?;
    let (input, _) = tag_no_case("PrivateToken").parse(input)?;
    let (input, _) = many1(space).parse(input)?;
    let (input, key_values) = separated_list1(
        alt((tag(","), tag(" "))), // header could be separated by a space in older specs, so we
        // need to support it
        parse_key_value,
    )
    .parse(input)?;

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

fn parse_private_tokens(input: &str) -> IResult<&str, Vec<(&str, Option<&str>)>> {
    separated_list1(tag(","), parse_private_token).parse(input)
}

fn parse_header_value<Nk: ArrayLength>(
    input: &str,
) -> Result<Vec<(Token<Nk>, Option<Extensions>)>, ParseError> {
    let (output, tokens) = parse_private_tokens(input).map_err(|_| ParseError::InvalidInput)?;
    if !output.is_empty() {
        return Err(ParseError::InvalidInput);
    }
    let tokens = tokens
        .into_iter()
        .map(|(token_value, extensions_value)| {
            let ext = extensions_value
                .map(|x| {
                    let decoded = URL_SAFE_INDIFFERENT
                        .decode(x)
                        .map_err(|_| ParseError::InvalidExtensions)?;
                    Extensions::tls_deserialize(&mut decoded.as_slice())
                        .map_err(|_| ParseError::InvalidExtensions)
                })
                .transpose()?;

            let token = Token::tls_deserialize(
                &mut URL_SAFE
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
    use http::HeaderValue;

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
            TokenType::PrivateP384,
            nonce,
            challenge_digest,
            token_key_id,
            *GenericArray::from_slice(&authenticator),
        );

        let extension = Extension::new(ExtensionType(5), b"hello world".to_vec());
        let extensions = Extensions::new(vec![extension]);
        let (header_name, header_value) =
            build_authorization_header_ext(&token, &extensions).unwrap();

        assert_eq!(header_name, http::header::AUTHORIZATION);

        let (token, maybe_extensions) =
            parse_authorization_header_ext::<U32>(&header_value).unwrap();
        assert_eq!(token.token_type(), TokenType::PrivateP384);
        assert_eq!(token.nonce(), nonce);
        assert_eq!(token.challenge_digest(), &challenge_digest);
        assert_eq!(token.token_key_id(), &token_key_id);
        assert_eq!(token.authenticator(), &authenticator);
        assert_eq!(maybe_extensions, Some(extensions));
    }

    /// This is the same test as `builder_parser_extensions_test`, but we replace the `, `
    /// separator with ` ` (single space) to make sure we can handle tokens generated by clients
    /// using an older version of the TOKEN-EXTENSION spec.
    #[test]
    fn rfc_9110_regression_test() {
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

        let extension = Extension::new(ExtensionType(5), b"hello world".to_vec());
        let extensions = Extensions::new(vec![extension]);
        let (header_name, header_value) =
            build_authorization_header_ext(&token, &extensions).unwrap();

        let header_value =
            HeaderValue::from_str(&header_value.to_str().unwrap().replace(", ", " ")).unwrap();

        assert_eq!(header_name, http::header::AUTHORIZATION);

        let (token, maybe_extensions) =
            parse_authorization_header_ext::<U32>(&header_value).unwrap();
        assert_eq!(token.token_type(), TokenType::PrivateP384);
        assert_eq!(token.nonce(), nonce);
        assert_eq!(token.challenge_digest(), &challenge_digest);
        assert_eq!(token.token_key_id(), &token_key_id);
        assert_eq!(token.authenticator(), &authenticator);
        assert_eq!(maybe_extensions, Some(extensions));
    }
}
