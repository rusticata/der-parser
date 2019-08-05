use nom::error::{ErrorKind, ParseError};

#[derive(Debug, PartialEq)]
pub enum BerError {
    /// Ber object does not have the expected type
    BerTypeError,
    BerValueError,

    InvalidTag,
    InvalidClass,
    InvalidLength,

    ConstructExpected,
    ConstructUnexpected,

    /// Ber integer is too large to fit in a native type. Use `as_bigint()`
    IntegerTooLarge,

    BerMaxDepth,

    /// When parsing a defined sequence, some items could not be found
    ObjectTooShort,

    DerConstraintFailed,

    UnknownTag,
    Unsupported,

    Custom(u32),

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
