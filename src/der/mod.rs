//! Distinguished Encoding Rules (DER) objects and parser
//!
//! All functions in this crate use BER parsing functions (see the `ber` module)
//! internally, adding constraints verification where needed.
//!
//! The objects `BerObject` and `DerObject` are the same (type alias): all BER functions,
//! combinators and macros can be used, and provide additional tools for DER parsing.

use crate::ber::{BerObject, BerTag};

mod multi;
mod parser;
mod tagged;
pub use crate::der::multi::*;
pub use crate::der::parser::*;
pub use crate::der::tagged::*;

/// DER tag (same as BER tag)
pub type DerTag = BerTag;

/// Representation of a DER-encoded (X.690) object
///
/// Note that a DER object is just a BER object, with additional constraints.
pub type DerObject<'a> = BerObject<'a>;
