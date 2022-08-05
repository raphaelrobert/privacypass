use std::io::Write;

use generic_array::{ArrayLength, GenericArray};
use pest::Parser;
use pest_derive::Parser;
use thiserror::*;
use tls_codec::{Deserialize, Error, Serialize, Size};

use crate::{ChallengeDigest, KeyId, Nonce, TokenType};

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

#[derive(Clone)]
pub struct Token<Nk: ArrayLength<u8>> {
    token_type: TokenType,
    nonce: Nonce,
    challenge_digest: ChallengeDigest,
    token_key_id: KeyId,
    authenticator: GenericArray<u8, Nk>,
}

impl<Nk: ArrayLength<u8>> Size for Token<Nk> {
    fn tls_serialized_len(&self) -> usize {
        self.token_type.tls_serialized_len()
            + self.nonce.tls_serialized_len()
            + self.challenge_digest.tls_serialized_len()
            + self.token_key_id.tls_serialized_len()
            + Nk::to_usize()
    }
}

impl<Nk: ArrayLength<u8>> Serialize for Token<Nk> {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        Ok(self.token_type.tls_serialize(writer)?
            + self.nonce.tls_serialize(writer)?
            + self.challenge_digest.tls_serialize(writer)?
            + self.token_key_id.tls_serialize(writer)?
            + writer.write(&self.authenticator[..])?)
    }
}

impl<Nk: ArrayLength<u8>> Deserialize for Token<Nk> {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let token_type = TokenType::tls_deserialize(bytes)?;
        let nonce = Nonce::tls_deserialize(bytes)?;
        let challenge_digest = ChallengeDigest::tls_deserialize(bytes)?;
        let token_key_id = KeyId::tls_deserialize(bytes)?;
        let mut authenticator = vec![0u8; Nk::to_usize()];
        let len = bytes.read(authenticator.as_mut_slice())?;
        if len != Nk::to_usize() {
            return Err(Error::InvalidVectorLength);
        }
        Ok(Token {
            token_type,
            nonce,
            challenge_digest,
            token_key_id,
            authenticator: GenericArray::clone_from_slice(&authenticator),
        })
    }
}

impl<Nk: ArrayLength<u8>> Token<Nk> {
    /// Creates a new Token.
    pub fn new(
        token_type: TokenType,
        nonce: Nonce,
        challenge_digest: ChallengeDigest,
        token_key_id: KeyId,
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
    pub fn token_type(&self) -> TokenType {
        self.token_type
    }

    /// Returns the nonce.
    pub fn nonce(&self) -> Nonce {
        self.nonce
    }

    /// Returns the challenge digest.
    pub fn challenge_digest(&self) -> &ChallengeDigest {
        &self.challenge_digest
    }

    /// Returns the token key ID.
    pub fn token_key_id(&self) -> u8 {
        self.token_key_id
    }

    /// Returns the authenticator.
    pub fn authenticator(&self) -> &[u8] {
        self.authenticator.as_ref()
    }
}

/// Builds a `Authorize` header according to the following scheme:
///
/// `PrivateToken token=...`
pub fn build_authorization_header<Nk: ArrayLength<u8>>(
    token: &Token<Nk>,
) -> Result<String, BuildError> {
    let value = format!(
        "PrivateToken token={}",
        base64::encode(
            token
                .tls_serialize_detached()
                .map_err(|_| BuildError::InvalidToken)?
        ),
    );
    Ok(value)
}

/// Building error for the `Authorization` header values
#[derive(Error, Debug)]
pub enum BuildError {
    #[error("Invalid token")]
    InvalidToken,
}

/// Parses an `Authorization` header according to the following scheme:
///
/// `PrivateToken token=...`
pub fn parse_authorization_header<Nk: ArrayLength<u8>>(
    value: &str,
) -> Result<Token<Nk>, ParseError> {
    AuthorizationParser::try_from_str(value)
}

/// Parsing error for the `WWW-Authenticate` header values
#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Invalid token")]
    InvalidToken,
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
property = { name ~ "=" ~ value }
token_param = { "PrivateToken" ~ "token=" ~ value }
authorization = {
    SOI ~
    token_param ~
    EOI
}
"#]
struct AuthorizationParser {}

impl AuthorizationParser {
    fn try_from_str<Nk: ArrayLength<u8>>(value: &str) -> Result<Token<Nk>, ParseError> {
        let mut authorization = Self::parse(Rule::authorization, value)
            .map_err(|_| ParseError::InvalidInput)?
            .next()
            .ok_or(ParseError::InvalidInput)?
            .into_inner();

        let token_param = authorization
            .next()
            .ok_or(ParseError::InvalidInput)?
            .into_inner()
            .next()
            .ok_or(ParseError::InvalidInput)?
            .as_str();
        let token = Token::tls_deserialize(
            &mut base64::decode(token_param)
                .map_err(|_| ParseError::InvalidToken)?
                .as_slice(),
        )
        .map_err(|_| ParseError::InvalidToken)?;

        Ok(token)
    }
}

#[test]
fn builder_parser_test() {
    use generic_array::typenum::U32;

    let nonce = [1u8; 32];
    let challenge_digest = [2u8; 32];
    let key_id = 3;
    let authenticator = [4u8; 32];
    let token = Token::<U32>::new(
        TokenType::Private,
        nonce,
        challenge_digest,
        key_id,
        GenericArray::clone_from_slice(&authenticator),
    );
    let header = build_authorization_header(&token).unwrap();

    let token = parse_authorization_header::<U32>(&header).unwrap();
    assert_eq!(token.token_type(), TokenType::Private);
    assert_eq!(token.nonce(), nonce);
    assert_eq!(token.challenge_digest(), &challenge_digest);
    assert_eq!(token.token_key_id(), key_id);
    assert_eq!(token.authenticator(), &authenticator);
}
