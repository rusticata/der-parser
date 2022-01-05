use super::{Class, Length};
use crate::error::BerError;
use asn1_rs::Tag;

/// BER object header (identifier and length)
#[derive(Clone, Debug)]
pub struct Header<'a> {
    /// Object class: universal, application, context-specific, or private
    pub(crate) class: Class,
    /// Constructed attribute: `true` if constructed, `false` if primitive
    pub(crate) constructed: bool,
    /// Tag number
    pub(crate) tag: Tag,
    /// Object length: definite or indefinite
    pub(crate) length: Length,

    /// Optionally, the raw encoding of the tag
    ///
    /// This is useful in some cases, where different representations of the same
    /// BER tags have different meanings (BER only)
    pub(crate) raw_tag: Option<&'a [u8]>,
}

impl<'a> Header<'a> {
    /// Build a new BER header
    pub fn new<Len: Into<Length>>(class: Class, constructed: bool, tag: Tag, length: Len) -> Self {
        Header {
            tag,
            constructed,
            class,
            length: length.into(),
            raw_tag: None,
        }
    }

    /// Get the BER object header's class.
    #[inline]
    pub const fn class(&self) -> Class {
        self.class
    }

    /// Set the BER object header's class.
    #[inline]
    pub fn set_class(&mut self, class: Class) {
        self.class = class;
    }

    /// Return error if `class` is not the expected class
    #[inline]
    pub const fn assert_class(&self, class: Class) -> Result<(), BerError> {
        if self.class as u8 == class as u8 {
            Ok(())
        } else {
            Err(BerError::unexpected_class(Some(class), self.class))
        }
    }

    /// Update header class
    #[inline]
    pub fn with_class(self, class: Class) -> Self {
        Header { class, ..self }
    }

    /// Get the BER object header's tag.
    #[inline]
    pub const fn tag(&self) -> Tag {
        self.tag
    }

    /// Set the BER object header's tag.
    #[inline]
    pub fn set_tag(&mut self, tag: Tag) {
        self.tag = tag;
    }

    /// Update header tag
    #[inline]
    pub fn with_tag(self, tag: Tag) -> Self {
        Header { tag, ..self }
    }

    /// Return error if `tag` is not the expected tag
    #[inline]
    pub const fn assert_tag(&self, tag: Tag) -> Result<(), BerError> {
        if self.tag.0 == tag.0 {
            Ok(())
        } else {
            Err(BerError::unexpected_tag(Some(tag), self.tag))
        }
    }

    /// Get the BER object header's length.
    #[inline]
    pub const fn length(&self) -> Length {
        self.length
    }

    /// Set the BER object header's length.
    #[inline]
    pub fn set_length(&mut self, length: Length) {
        self.length = length;
    }

    /// Update header length
    #[inline]
    pub fn with_len(self, len: Length) -> Self {
        Header {
            length: len,
            ..self
        }
    }

    /// Get a reference to the BER object header's tag.
    #[inline]
    pub const fn raw_tag(&self) -> Option<&'a [u8]> {
        self.raw_tag
    }

    /// Update header to add reference to raw tag
    #[inline]
    pub fn with_raw_tag(self, raw_tag: Option<&'a [u8]>) -> Self {
        Header { raw_tag, ..self }
    }

    /// Test if object class is Universal
    #[inline]
    pub const fn is_universal(&self) -> bool {
        self.class as u8 == Class::Universal as u8
    }
    /// Test if object class is Application
    #[inline]
    pub const fn is_application(&self) -> bool {
        self.class as u8 == Class::Application as u8
    }
    /// Test if object class is Context-specific
    #[inline]
    pub const fn is_contextspecific(&self) -> bool {
        self.class as u8 == Class::ContextSpecific as u8
    }
    /// Test if object class is Private
    #[inline]
    pub const fn is_private(&self) -> bool {
        self.class as u8 == Class::Private as u8
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
        Header {
            constructed,
            ..self
        }
    }

    /// Return error if object is not constructed
    #[inline]
    pub const fn assert_constructed(&self) -> Result<(), BerError> {
        if self.is_constructed() {
            Ok(())
        } else {
            Err(BerError::ConstructExpected)
        }
    }

    /// Return error if object is not primitive
    #[inline]
    pub const fn assert_primitive(&self) -> Result<(), BerError> {
        if self.is_primitive() {
            Ok(())
        } else {
            Err(BerError::ConstructUnexpected)
        }
    }
}

/// Compare two BER headers. `len` fields are compared only if both objects have it set (same for `raw_tag`)
impl<'a> PartialEq<Header<'a>> for Header<'a> {
    fn eq(&self, other: &Header) -> bool {
        self.class == other.class
            && self.tag == other.tag
            && self.constructed == other.constructed
            && {
                if self.length.is_null() && other.length.is_null() {
                    self.length == other.length
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
