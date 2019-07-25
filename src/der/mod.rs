//! Basic Encoding Rules (BER) objects and parser

use crate::ber::{BerObject, BerTag};

mod parser;
pub use crate::der::parser::*;

/// DER tag (same as BER tag)
pub type DerTag = BerTag;

/// Representation of a DER-encoded (X.690) object
///
/// Note that a DER object is just a BER object, with additional constraints.
pub type DerObject<'a> = BerObject<'a>;
