//! Privacy Pass HTTP Authentication Scheme

use nom::{
    IResult, Parser,
    branch::alt,
    bytes::complete::{is_a, tag, take_while1},
    combinator::verify,
    multi::{many0, many1},
    sequence::delimited,
};
use std::str::FromStr;

pub mod authenticate;
pub mod authorize;

pub(crate) fn space(input: &str) -> IResult<&str, &str> {
    is_a(" \t")(input)
}

pub(crate) fn opt_spaces(input: &str) -> IResult<&str, Vec<&str>> {
    many0(space).parse(input)
}

// parses comma separation between header list elements and handles empty elements by collapsing multiple commas into one.
// required by RFC 9110 section 5.6.1.2
pub(crate) fn comma_sep(input: &str) -> IResult<&str, ()> {
    let (input, _) = many1((opt_spaces, tag(","))).parse(input)?;
    Ok((input, ()))
}

pub(crate) fn parse_u32(input: &str) -> Result<u32, std::num::ParseIntError> {
    u32::from_str(input)
}

pub(crate) fn base64_char(input: &str) -> IResult<&str, &str> {
    nom::bytes::complete::is_a("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")(
        input,
    )
}

pub(crate) fn key_name(input: &str) -> IResult<&str, &str> {
    let (input, s) =
        verify(take_while1(is_alpha_or_dash), surrounded_by_alphanumeric).parse(input)?;
    Ok((input, s))
}

pub(crate) fn is_alpha_or_dash(c: char) -> bool {
    c.is_alphanumeric() || c == '-'
}

pub(crate) fn surrounded_by_alphanumeric(input: &str) -> bool {
    let dash = '-';

    if input.starts_with(dash) || input.ends_with(dash) {
        return false;
    }

    if input.contains("--") {
        return false;
    }

    true
}

pub(crate) fn unquote(input: &str) -> IResult<&str, &str> {
    delimited(tag("\""), base64_char, tag("\"")).parse(input)
}

pub(crate) fn maybe_unquote(input: &str) -> IResult<&str, &str> {
    alt((unquote, base64_char)).parse(input)
}
