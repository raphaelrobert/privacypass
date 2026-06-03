//! Types and functions related to the Extensions parameter.
//!
//! Specified in `draft-ietf-privacypass-auth-scheme-extensions`.

use std::io::{Read, Write};
use tls_codec::{Deserialize, Serialize, Size, TlsByteVecU16, TlsVecU16};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

/// Type of extension.
///
/// Extension types are to be defined by the client, not by this crate
#[derive(Clone, Copy, Debug, PartialEq, Eq, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct ExtensionType(pub u16);

impl ExtensionType {
    /// Reserved by `draft-ietf-privacypass-auth-scheme-extensions`
    pub const RESERVED: ExtensionType = ExtensionType(0);
}

/// A single extension.
///
/// Contains opaque byte data whose semantics are determined by the type.
#[derive(Clone, Debug, PartialEq, Eq, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct Extension {
    extension_type: ExtensionType,
    extension_data: TlsByteVecU16,
}

impl Extension {
    /// Create a new Extension.
    ///
    /// `data` should be byte data whose semantics are determined by `ext_type`.
    pub fn new(ext_type: ExtensionType, data: Vec<u8>) -> Extension {
        Extension {
            extension_type: ext_type,
            extension_data: TlsByteVecU16::new(data),
        }
    }
}

/// A set of extensions.
///
/// Contains a list of Extension values.
#[derive(Clone, Debug, PartialEq, Eq, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct Extensions {
    extensions: TlsVecU16<Extension>,
}

impl Extensions {
    /// Create a new `Extensions`.
    pub fn new(extensions: Vec<Extension>) -> Extensions {
        Extensions {
            extensions: TlsVecU16::new(extensions),
        }
    }
}

/// Denotes whether a certain extension type is required or optional.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtensionEntry {
    is_required: bool,
    extension_type: ExtensionType,
}

// we need to implement these by hand because tls_codec doesn't ship an impl of these for `bool`
impl Size for ExtensionEntry {
    fn tls_serialized_len(&self) -> usize {
        (self.is_required as u8).tls_serialized_len() + self.extension_type.tls_serialized_len()
    }
}

impl Serialize for ExtensionEntry {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Ok((self.is_required as u8).tls_serialize(writer)?
            + self.extension_type.tls_serialize(writer)?)
    }
}

impl Deserialize for ExtensionEntry {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        // extensions spec requires that bools are either 0 or 1
        let is_required = match u8::tls_deserialize(bytes)? {
            0 => false,
            1 => true,
            _ => return Err(tls_codec::Error::InvalidInput),
        };

        let extension_type = ExtensionType::tls_deserialize(bytes)?;

        Ok(Self {
            is_required,
            extension_type,
        })
    }
}

impl ExtensionEntry {
    /// Creates a new `ExtensionEntry`.
    pub fn new(is_required: bool, extension_type: ExtensionType) -> ExtensionEntry {
        Self {
            is_required,
            extension_type,
        }
    }
}

/// A set of extension entries.
#[derive(Clone, Debug, PartialEq, Eq, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct ExtensionSet {
    extension_types: TlsVecU16<ExtensionEntry>,
}

impl ExtensionSet {
    /// Creates a new `ExtensionSet`
    pub fn new(extension_types: Vec<ExtensionEntry>) -> ExtensionSet {
        ExtensionSet {
            extension_types: TlsVecU16::new(extension_types),
        }
    }
}
