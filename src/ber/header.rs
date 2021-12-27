use super::{BerClass, Length, BerTag};

/// BER object header (identifier and length)
#[derive(Clone, Debug)]
pub struct BerObjectHeader<'a> {
    /// Object class: universal, application, context-specific, or private
    pub class: BerClass,
    /// Constructed attribute: 1 if constructed, else 0
    pub structured: u8,
    /// Tag number
    pub tag: BerTag,
    /// Object length: definite or indefinite
    pub len: Length,

    /// Optionally, the raw encoding of the tag
    ///
    /// This is useful in some cases, where different representations of the same
    /// BER tags have different meanings (BER only)
    pub raw_tag: Option<&'a [u8]>,
}
