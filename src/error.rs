//! Error type for BER/DER parsers

use nom::error::{ErrorKind, ParseError};

/// Error for BER/DER parsers
#[derive(Debug, PartialEq)]
pub enum BerError {
    /// BER object does not have the expected type
    BerTypeError,
    /// BER object does not have the expected value
    BerValueError,

    InvalidTag,
    InvalidClass,
    InvalidLength,

    /// DER object was expected to be constructed (and found to be primitive)
    ConstructExpected,
    /// DER object was expected to be primitive (and found to be constructed)
    ConstructUnexpected,

    /// BER integer is too large to fit in a native type. Use `as_bigint()`
    IntegerTooLarge,

    /// BER recursive parsing reached maximum depth (See
    /// [MAX_RECURSION](../ber/constant.MAX_RECURSION.html))
    BerMaxDepth,

    /// When parsing a defined sequence, some items could not be found
    ObjectTooShort,

    /// A DER constraint failed (object may be using BER encoding?)
    DerConstraintFailed,

    UnknownTag,
    /// Feature is not yet implemented
    Unsupported,

    /// Custom error type left for parsers on top of this crate, so they can handle their custom
    /// errors
    Custom(u32),

    /// Error raised by the underlying nom parser
    NomError(ErrorKind),
}

impl<I> ParseError<I> for BerError {
    fn from_error_kind(_input: I, kind: ErrorKind) -> Self {
        BerError::NomError(kind)
    }
    fn append(_input: I, kind: ErrorKind, _other: Self) -> Self {
        BerError::NomError(kind)
    }
}
