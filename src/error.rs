#[derive(Debug,PartialEq)]
pub enum DerError {
    /// Der object does not have the expected type
    DerTypeError,
    DerValueError,

    InvalidTag,
    InvalidLength,

    /// Der integer is too large to fit in a native type. Use `as_bigint()`
    IntegerTooLarge,
}
