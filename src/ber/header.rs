use super::{Class, Length, Tag};
use crate::error::BerError;

/// BER object header (identifier and length)
#[derive(Clone, Debug)]
pub struct BerObjectHeader<'a> {
    /// Object class: universal, application, context-specific, or private
    pub(crate) class: Class,
    /// Constructed attribute: `true` if constructed, `false` if primitive
    pub(crate) constructed: bool,
    /// Tag number
    pub(crate) tag: Tag,
    /// Object length: definite or indefinite
    pub len: Length,

    /// Optionally, the raw encoding of the tag
    ///
    /// This is useful in some cases, where different representations of the same
    /// BER tags have different meanings (BER only)
    pub(crate) raw_tag: Option<&'a [u8]>,
}

impl<'a> BerObjectHeader<'a> {
    /// Build a new BER header
    pub fn new<Len: Into<Length>>(class: Class, constructed: bool, tag: Tag, len: Len) -> Self {
        BerObjectHeader {
            tag,
            constructed,
            class,
            len: len.into(),
            raw_tag: None,
        }
    }

    /// Get the BER object header's class.
    #[inline]
    pub const fn class(&self) -> Class {
        self.class
    }

    /// Update header class
    #[inline]
    pub fn with_class(self, class: Class) -> Self {
        BerObjectHeader { class, ..self }
    }

    /// Get the BER object header's tag.
    #[inline]
    pub const fn tag(&self) -> Tag {
        self.tag
    }

    /// Update header tag
    #[inline]
    pub fn with_tag(self, tag: Tag) -> Self {
        BerObjectHeader { tag, ..self }
    }

    /// Return error if tag is not the expected tag
    #[inline]
    pub const fn assert_tag(&self, tag: Tag) -> Result<(), BerError> {
        if self.tag.0 == tag.0 {
            Ok(())
        } else {
            Err(BerError::UnexpectedTag(tag))
        }
    }

    /// Get the BER object header's length.
    #[inline]
    pub const fn length(&self) -> Length {
        self.len
    }

    /// Update header length
    #[inline]
    pub fn with_len(self, len: Length) -> Self {
        BerObjectHeader { len, ..self }
    }

    /// Get a reference to the BER object header's tag.
    #[inline]
    pub const fn raw_tag(&self) -> Option<&'a [u8]> {
        self.raw_tag
    }

    /// Update header to add reference to raw tag
    #[inline]
    pub fn with_raw_tag(self, raw_tag: Option<&'a [u8]>) -> Self {
        BerObjectHeader { raw_tag, ..self }
    }

    /// Test if object class is Universal
    #[inline]
    pub fn is_universal(&self) -> bool {
        self.class == Class::Universal
    }
    /// Test if object class is Application
    #[inline]
    pub fn is_application(&self) -> bool {
        self.class == Class::Application
    }
    /// Test if object class is Context-specific
    #[inline]
    pub fn is_contextspecific(&self) -> bool {
        self.class == Class::ContextSpecific
    }
    /// Test if object class is Private
    #[inline]
    pub fn is_private(&self) -> bool {
        self.class == Class::Private
    }

    /// Test if object is primitive
    #[inline]
    pub const fn is_primitive(&self) -> bool {
        !self.constructed
    }
    /// Test if object is constructed
    #[inline]
    pub const fn is_constructed(&self) -> bool {
        self.constructed
    }

    /// Set the BER object header's constructed attribute.
    #[inline]
    pub const fn constructed(&self) -> bool {
        self.constructed
    }
    /// Set the BER object header's constructed attribute.
    #[inline]
    pub fn set_constructed(&mut self, constructed: bool) {
        self.constructed = constructed;
    }

    /// Update header tag
    #[inline]
    pub fn with_constructed(self, constructed: bool) -> Self {
        BerObjectHeader {
            constructed,
            ..self
        }
    }
}

/// Compare two BER headers. `len` fields are compared only if both objects have it set (same for `raw_tag`)
impl<'a> PartialEq<BerObjectHeader<'a>> for BerObjectHeader<'a> {
    fn eq(&self, other: &BerObjectHeader) -> bool {
        self.class == other.class
            && self.tag == other.tag
            && self.constructed == other.constructed
            && {
                if self.len.is_null() && other.len.is_null() {
                    self.len == other.len
                } else {
                    true
                }
            }
            && {
                // it tag is present for both, compare it
                if self.raw_tag.xor(other.raw_tag).is_none() {
                    self.raw_tag == other.raw_tag
                } else {
                    true
                }
            }
    }
}
