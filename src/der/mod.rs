//! Distinguished Encoding Rules (DER) objects and parser
//!
//! All functions in this crate use BER parsing functions (see the `ber` module)
//! internally, adding constraints verification where needed.
//!
//! The objects `BerObject` and `DerObject` are the same (type alias): all BER functions,
//! combinators and macros can be used, and provide additional tools for DER parsing.

use crate::ber::{BerClass, BerObject, BerObjectContent, BerObjectHeader, BerTag};

mod multi;
mod parser;
mod tagged;
pub use crate::der::multi::*;
pub use crate::der::parser::*;
pub use crate::der::tagged::*;

/// DER Object class of tag (same as `BerClass`)
pub type DerClass = BerClass;

/// DER tag (same as BER tag)
pub type DerTag = BerTag;

/// Representation of a DER-encoded (X.690) object
///
/// Note that a DER object is just a BER object, with additional constraints.
pub type DerObject<'a> = BerObject<'a>;

/// DER object header (identifier and length)
///
/// This is the same object as `BerObjectHeader`.
pub type DerObjectHeader<'a> = BerObjectHeader<'a>;

/// BER object content
///
/// This is the same object as `BerObjectContent`.
pub type DerObjectContent<'a> = BerObjectContent<'a>;
