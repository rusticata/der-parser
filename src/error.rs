#[derive(Debug, PartialEq)]
pub enum BerError {
    /// Ber object does not have the expected type
    BerTypeError,
    BerValueError,

    InvalidTag,
    InvalidLength,

    /// Ber integer is too large to fit in a native type. Use `as_bigint()`
    IntegerTooLarge,

    BerMaxDepth,

    DerConstraintFailed,

    Unsupported,
}

pub type DerError = BerError;

/// Unexpected BER tag
pub const BER_TAG_ERROR: u32 = 128;
/// Unexpected BER class
pub const BER_CLASS_ERROR: u32 = 129;
/// Unexpected BER structured flag
pub const BER_STRUCT_ERROR: u32 = 130;

/// Unknown or unsupported BER tag
pub const BER_TAG_UNKNOWN: u32 = 131;

/// Invalid length for BER object
pub const BER_INVALID_LENGTH: u32 = 132;

/// Items contained in a structured object do not fill the entire container object
pub const BER_OBJ_TOOSHORT: u32 = 133;

/// Integer too large
pub const BER_INTEGER_TOO_LARGE: u32 = 134;

/// Unsupported object (parsing error)
pub const BER_UNSUPPORTED: u32 = 150;

/// Max recursion depth exceeded
pub const BER_MAX_DEPTH : u32 = 151;

/// DER constraint violation
pub const DER_CONSTRAINT_FAIL: u32 = 160;
