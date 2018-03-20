//! # DER Parser
//!
//! A DER (X.690) parser, implemented with the [nom](https://github.com/Geal/nom)
//! parser combinator framework.
//!
//! The code is available on [Github](https://github.com/rusticata/der-parser)
//! and is part of the [Rusticata](https://github.com/rusticata) project.
//!
//! # DER parser design
//!
//! There are two different approaches for parsing DER objects: reading the objects recursively as
//! long as the tags are known, or specifying a description of the expected objects (generally from
//! the ASN.1 description).
//!
//! The first parsing method can be done using the [`parse_der`](fn.parse_der.html) method.
//! However, it cannot fully parse all objects, especially those containing IMPLICIT, OPTIONAL, or
//! DEFINED BY items.
//!
//! ```rust,no_run
//! # #[macro_use] extern crate der_parser;
//! use der_parser::parse_der;
//!
//! # fn main() {
//! let bytes = [ 0x30, 0x0a,
//!               0x02, 0x03, 0x01, 0x00, 0x01,
//!               0x02, 0x03, 0x01, 0x00, 0x00,
//! ];
//!
//! let parsed = parse_der(&bytes);
//! # }
//! ```
//!
//! The second (and preferred) parsing method is to specify the expected objects recursively. The
//! following macros can be used:
//! [`parse_der_sequence_defined`](macro.parse_der_sequence_defined.html) and similar functions,
//! [`parse_der_struct`](macro.parse_der_struct.html), etc.
//!
//! For example, to read a sequence containing two integers:
//!
//! ```rust,no_run
//! # #[macro_use] extern crate nom;
//! # #[macro_use] extern crate rusticata_macros;
//! # #[macro_use] extern crate der_parser;
//! use der_parser::*;
//! use nom::{IResult,Err,ErrorKind};
//!
//! # fn main() {
//! fn localparse_seq(i:&[u8]) -> IResult<&[u8],DerObject> {
//!     parse_der_sequence_defined!(i,
//!         parse_der_integer,
//!         parse_der_integer
//!     )
//! }
//! let bytes = [ 0x30, 0x0a,
//!               0x02, 0x03, 0x01, 0x00, 0x01,
//!               0x02, 0x03, 0x01, 0x00, 0x00,
//! ];
//! let parsed = localparse_seq(&bytes);
//! # }
//! ```
//!
//! All functions return an `IResult` object from `nom`: the parsed
//! [`DerObject`](struct.DerObject.html), an `Incomplete` value, or an error.
//!
//! # Notes
//!
//! - The DER constraints are not enforced or verified. Because of that, this parser is mostly
//! compatible with BER.
//! - DER integers can be of any size, so it is not possible to store them as simple integers (they
//! are stored as raw bytes). To get a simple value, use
//! [`DerObject::as_u32`](struct.DerObject.html#method.as_u32) (knowning that this method will
//! return an error if the integer is too large), or use the `bigint` feature of this crate and use
//! [`DerObject::as_bigint`](struct.DerObject.html#method.as_bigint).
//!
//! # References
//!
//! - [[X.680]](http://www.itu.int/rec/T-REC-X.680/en) Abstract Syntax Notation One (ASN.1):
//!   Specification of basic notation.
//! - [[X.690]](https://www.itu.int/rec/T-REC-X.690/en) ASN.1 encoding rules: Specification of
//!   Basic Encoding Rules (BER), Canonical Encoding Rules (CER) and Distinguished Encoding Rules
//!   (DER).

#![deny(/*missing_docs,*/unsafe_code,
        unstable_features,
        unused_import_braces, unused_qualifications)]

#[macro_use]
extern crate nom;

#[macro_use]
extern crate rusticata_macros;

#[macro_use] mod macros;

mod der;
pub use der::*;

mod der_parser;
pub use der_parser::*;

mod der_print;
pub use der_print::*;

mod error;
pub use error::*;

pub mod oid;

#[cfg(feature="bigint")]
extern crate num;
