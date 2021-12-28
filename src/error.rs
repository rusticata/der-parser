//! Error type for BER/DER parsers

use crate::ber::{BerObject, Class, Tag};
use crate::der::DerObject;
use displaydoc::Display;
use nom::error::{ErrorKind, FromExternalError, ParseError};
use nom::IResult;
use thiserror::Error;

/// Holds the result of parsing functions
///
/// `O` is the output type, and defaults to a `BerObject`.
///
/// Note that this type is also a `Result`, so usual functions (`map`, `unwrap` etc.) are available.
///
/// This type is a wrapper around nom's IResult type
pub type BerResult<'a, O = BerObject<'a>> = IResult<&'a [u8], O, BerError>;

/// Holds the result of parsing functions (DER)
///
/// Note that this type is also a `Result`, so usual functions (`map`, `unwrap` etc.) are available.
pub type DerResult<'a> = BerResult<'a, DerObject<'a>>;

/// Error for BER/DER parsers
#[derive(Debug, PartialEq, Copy, Clone, Display, Error)]
#[ignore_extra_doc_attributes]
pub enum BerError {
    /// BER object does not have the expected type
    BerTypeError,
    /// BER object does not have the expected value
    BerValueError,

    /// Invalid tag encoding or value
    InvalidTag,
    /// Invalid Class encoding or value
    InvalidClass,
    /// Invalid Length encoding or value
    InvalidLength,

    /// Indefinite length encountered, while a definite length was expected
    IndefiniteLengthUnexpected,

    /// DER object was expected to be constructed (and found to be primitive)
    ConstructExpected,
    /// DER object was expected to be primitive (and found to be constructed)
    ConstructUnexpected,

    /// BER string has characters forbidden in standard
    StringInvalidCharset,

    /// BER integer is too large to fit in a native type. Use `as_bigint()`
    IntegerTooLarge,
    /// BER integer is negative, while an unsigned integer was requested
    IntegerNegative,

    /// BER recursive parsing reached maximum depth
    /// (See [MAX_RECURSION](../ber/constant.MAX_RECURSION.html))
    BerMaxDepth,

    /// When parsing a defined sequence, some items could not be found
    ObjectTooShort,

    /// A DER constraint failed (object may be using BER encoding?)
    DerConstraintFailed,

    /// Unknown tag
    UnknownTag,
    /// Feature is not yet implemented
    Unsupported,

    /// Invalid class (expected {expected:?}, found {found:?})
    UnexpectedClass { expected: Class, found: Class },
    /// Invalid tag (expected {expected:?}, found {found:?})
    UnexpectedTag { expected: Tag, found: Tag },

    /// Custom error: {0}
    ///
    /// This type is left for parsers on top of this crate, so they can handle their custom errors.
    Custom(u32),

    /// Error raised by the underlying nom parser: {0:?}
    NomError(ErrorKind),
}

impl BerError {
    /// Build an error from the provided unexpected class
    #[inline]
    pub const fn unexpected_class(expected: Class, found: Class) -> Self {
        Self::UnexpectedClass { expected, found }
    }

    /// Build an error from the provided unexpected tag
    #[inline]
    pub const fn unexpected_tag(expected: Tag, found: Tag) -> Self {
        Self::UnexpectedTag { expected, found }
    }
}

impl From<BerError> for nom::Err<BerError> {
    #[inline]
    fn from(e: BerError) -> nom::Err<BerError> {
        nom::Err::Error(e)
    }
}

impl<I> ParseError<I> for BerError {
    fn from_error_kind(_input: I, kind: ErrorKind) -> Self {
        BerError::NomError(kind)
    }
    fn append(_input: I, kind: ErrorKind, _other: Self) -> Self {
        BerError::NomError(kind)
    }
}

impl<I, E> FromExternalError<I, E> for BerError {
    fn from_external_error(_input: I, kind: ErrorKind, _e: E) -> BerError {
        BerError::NomError(kind)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use std::boxed::Box;
    use std::error::Error;

    #[test]
    fn test_unwrap_bererror() {
        let e = BerError::IntegerTooLarge;
        // println!("{}", e);
        let _: Result<(), Box<dyn Error>> = Err(Box::new(e));
    }
}
