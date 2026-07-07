//! Types and functions related to the Extensions parameter.
//!
//! Specified in `draft-ietf-privacypass-auth-scheme-extensions-03`.

use std::{
    collections::HashSet,
    io::{Read, Write},
};
use thiserror::Error;
use tls_codec::{Deserialize, Serialize, Size, TlsByteVecU16, TlsVecU16};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::common::errors::CreateExtensionsError;

/// Type of extension as specified in
/// [`draft-ietf-privacypass-auth-scheme-extensions-03` &sect;3](https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-auth-scheme-extensions-03#section-3):
///
/// ```c
/// enum {
///     reserved(0),
///     (65535)
/// } ExtensionType;
/// ```
///
/// Extension types are to be defined by the client, not by this crate
#[derive(Clone, Copy, Debug, PartialEq, Eq, TlsSize, TlsSerialize, TlsDeserialize, Hash)]
pub struct ExtensionType(pub u16);

impl ExtensionType {
    /// Defined in
    /// [`draft-ietf-privacypass-auth-scheme-extensions-03` &sect;3](https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-auth-scheme-extensions-03#section-3)
    pub const RESERVED: ExtensionType = ExtensionType(0);
}

/// A single extension as specified in
/// [`draft-ietf-privacypass-auth-scheme-extensions-03` &sect;3](https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-auth-scheme-extensions-03#section-3):
///
/// ```c
/// struct {
///     ExtensionType extension_type;
///     opaque extension_data<0..2^16-1>;
/// } Extension;
/// ```
///
/// Contains opaque byte data whose semantics are determined by the extension type.
#[derive(Clone, Debug, PartialEq, Eq, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct Extension {
    extension_type: ExtensionType,
    extension_data: TlsByteVecU16,
}

impl Extension {
    /// Create a new Extension.
    ///
    /// `data` should be byte data whose semantics are determined by `ext_type`.
    ///
    /// Returns an error if data is more than 65535 bytes long
    pub fn new(ext_type: ExtensionType, data: Vec<u8>) -> Result<Extension, CreateExtensionsError> {
        if data.len() > 65535 {
            return Err(CreateExtensionsError::InvalidSize);
        }

        Ok(Extension {
            extension_type: ext_type,
            extension_data: TlsByteVecU16::new(data),
        })
    }

    /// Returns this extension's type
    pub fn extension_type(&self) -> ExtensionType {
        self.extension_type
    }

    /// Returns a slice containing this extension's data
    pub fn extension_data(&self) -> &[u8] {
        self.extension_data.as_slice()
    }
}

/// A set of extensions as specified in
/// [`draft-ietf-privacypass-auth-scheme-extensions-03` &sect;3](https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-auth-scheme-extensions-03#section-3):
///
/// ```c
/// struct {
///     Extension extensions<0..2^16-1>;
/// } Extensions;
/// ```
///
/// Contains a list of Extension values.
#[derive(Clone, Debug, PartialEq, Eq, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct Extensions {
    extensions: TlsVecU16<Extension>,
}

impl Extensions {
    /// Create a new `Extensions`.
    ///
    /// The given extensions MUST be sorted and must not contain [`ExtensionType::RESERVED`].
    /// Extension types MAY be repeated.
    ///
    /// This function will error if the above conditions are not met
    pub fn new(extensions: Vec<Extension>) -> Result<Extensions, CreateExtensionsError> {
        if !extensions.is_sorted_by(|a, b| a.extension_type.0 <= b.extension_type.0) {
            return Err(CreateExtensionsError::ExtensionsUnsorted);
        }

        #[cfg(not(any(test, feature = "test-utils")))]
        if extensions
            .iter()
            .any(|x| x.extension_type.0 == ExtensionType::RESERVED.0)
        {
            return Err(CreateExtensionsError::InvalidType);
        }

        let v = TlsVecU16::new(extensions);
        // -2 for the vec's length prefix
        if v.tls_serialized_len() - 2 > 65535 {
            return Err(CreateExtensionsError::InvalidSize);
        }

        Ok(Extensions { extensions: v })
    }

    /// Returns a slice with the contained extensions
    pub fn extensions(&self) -> &[Extension] {
        self.extensions.as_slice()
    }
}

/// An extension entry as specified in
/// [`draft-ietf-privacypass-auth-scheme-extensions-03` &sect;4](https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-auth-scheme-extensions-03#section-4):
///
/// ```c
/// struct {
///     enum { false(0), true(1) } Bool;
///     Bool is_required;
///     ExtensionType extension_type;
/// } ExtensionEntry;
/// ```
///
/// Denotes whether a given extension type is required or optional.
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

    /// Returns whether this extension is required
    pub fn is_required(&self) -> bool {
        self.is_required
    }

    /// Returns this entry's extension type
    pub fn extension_type(&self) -> ExtensionType {
        self.extension_type
    }
}

/// A set of extension entries as specified in
/// [`draft-ietf-privacypass-auth-scheme-extensions-03` &sect;4](https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-auth-scheme-extensions-03#section-4):
///
/// ```c
/// struct {
///     ExtensionEntry extension_types<0..2^16-1>;
/// } ExtensionSet;
/// ```
#[derive(Clone, Debug, PartialEq, Eq, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct ExtensionSet {
    extension_types: TlsVecU16<ExtensionEntry>,
}

/// Error that occurs during extension negotiation
#[derive(Error, Debug)]
pub enum NegotiationError {
    /// A required extension was missing
    #[error("Missing required extension type: {extension_type:?}")]
    MissingExtensionType {
        /// Extension type that was required
        extension_type: ExtensionType,
    },
}

impl ExtensionSet {
    /// Creates a new `ExtensionSet`
    pub fn new(extension_types: Vec<ExtensionEntry>) -> ExtensionSet {
        ExtensionSet {
            extension_types: TlsVecU16::new(extension_types),
        }
    }

    /// Validate that the required extension types in this extension set are present in the given
    /// extensions.
    ///
    /// This validation enables the behavior described in
    /// `draft-ietf-privacypass-auth-scheme-extensions-03` &sect; 4, where "a client should expect to
    /// be rejected if not providing required extensions".
    ///
    /// Returns an error if any required extension type is missing
    pub fn validate(&self, extensions: &Extensions) -> Result<(), NegotiationError> {
        let types: HashSet<ExtensionType> = extensions
            .extensions
            .iter()
            .map(|e| e.extension_type)
            .collect();
        let required = self
            .extension_types
            .iter()
            .filter(|e| e.is_required)
            .map(|e| e.extension_type);

        for required_type in required {
            if !types.contains(&required_type) {
                return Err(NegotiationError::MissingExtensionType {
                    extension_type: required_type,
                });
            }
        }

        Ok(())
    }

    /// Returns a slice with the contained extension entries
    pub fn extension_types(&self) -> &[ExtensionEntry] {
        self.extension_types.as_slice()
    }
}
