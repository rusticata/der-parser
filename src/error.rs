#[derive(Debug,PartialEq)]
pub enum DerError {
    /// Der object does not have the expected type
    DerTypeError,
    DerValueError,

    InvalidTag,
    InvalidLength,

    /// Der integer is too large to fit in a native type. Use `as_bigint()`
    IntegerTooLarge,

    Unsupported,
}

/// Unexpected DER tag
pub const DER_TAG_ERROR : u32 = 128;
/// Unexpected DER class
pub const DER_CLASS_ERROR : u32 = 129;
/// Unexpected DER structured flag
pub const DER_STRUCT_ERROR : u32 = 130;

/// Unknown or unsupported DER tag
pub const DER_TAG_UNKNOWN : u32 = 131;

/// Invalid length for DER object
pub const DER_INVALID_LENGTH : u32 = 132;

/// Items contained in a structured object do not fill the entire container object
pub const DER_OBJ_TOOSHORT : u32 = 133;

/// Integer too large
pub const DER_INTEGER_TOO_LARGE : u32 = 134;

/// Unsupported object (parsing error)
pub const DER_UNSUPPORTED : u32 = 150;
