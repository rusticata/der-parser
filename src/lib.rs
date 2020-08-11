//! [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
//! [![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
//! [![docs.rs](https://docs.rs/der-parser/badge.svg)](https://docs.rs/der-parser)
//! [![crates.io](https://img.shields.io/crates/v/der-parser.svg)](https://crates.io/crates/der-parser)
//! [![Download numbers](https://img.shields.io/crates/d/der-parser.svg)](https://crates.io/crates/der-parser)
//! [![Travis CI](https://travis-ci.org/rusticata/der-parser.svg?branch=master)](https://travis-ci.org/rusticata/der-parser)
//! [![AppVeyor CI](https://ci.appveyor.com/api/projects/status/github/rusticata/der-parser?svg=true)](https://ci.appveyor.com/project/chifflier/der-parser)
//! [![dependency status](https://deps.rs/crate/der-parser/4.0.2/status.svg)](https://deps.rs/crate/der-parser/4.0.2)
//!
//! # BER/DER Parser
//!
//! A parser for Basic Encoding Rules (BER [[X.690]]) and Distinguished Encoding Rules(DER
//! [[X.690]]), implemented with the [nom](https://github.com/Geal/nom) parser combinator
//! framework.
//!
//! It is written in pure Rust, fast, and makes extensive use of zero-copy. A lot of care is taken
//! to ensure security and safety of this crate, including design (recursion limit, defensive
//! programming), tests, and fuzzing. It also aims to be panic-free.
//!
//! The code is available on [Github](https://github.com/rusticata/der-parser)
//! and is part of the [Rusticata](https://github.com/rusticata) project.
//!
//! # DER parser design
//!
//! There are two different approaches for parsing DER objects: reading the objects recursively as
//! long as the tags are known, or specifying a description of the expected objects (generally from
//! the [ASN.1][X.680] description).
//!
//! The first parsing method can be done using the [`parse_ber`](ber/fn.parse_ber.html) and
//! [`parse_der`](der/fn.parse_der.html) methods.
//! It is useful when decoding an arbitrary DER object.
//! However, it cannot fully parse all objects, especially those containing IMPLICIT, OPTIONAL, or
//! DEFINED BY items.
//!
//! ```rust
//! # #[macro_use] extern crate der_parser;
//! use der_parser::parse_der;
//!
//! let bytes = [ 0x30, 0x0a,
//!               0x02, 0x03, 0x01, 0x00, 0x01,
//!               0x02, 0x03, 0x01, 0x00, 0x00,
//! ];
//!
//! let parsed = parse_der(&bytes);
//! ```
//!
//! The second (and preferred) parsing method is to specify the expected objects recursively. The
//! following macros can be used:
//! [`parse_der_sequence_defined`](macro.parse_der_sequence_defined.html) and similar functions,
//! [`parse_der_struct`](macro.parse_der_struct.html), etc.
//!
//! For example, to read a sequence containing two integers:
//!
//! ```rust
//! # #[macro_use] extern crate der_parser;
//! use der_parser::ber::*;
//! use der_parser::error::BerResult;
//!
//! fn localparse_seq(i:&[u8]) -> BerResult {
//!     parse_der_sequence_defined!(i,
//!         parse_ber_integer >>
//!         parse_ber_integer
//!     )
//! }
//!
//! let bytes = [ 0x30, 0x0a,
//!               0x02, 0x03, 0x01, 0x00, 0x01,
//!               0x02, 0x03, 0x01, 0x00, 0x00,
//! ];
//! let parsed = localparse_seq(&bytes);
//! ```
//!
//! All functions return a [`BerResult`](error/type.BerResult.html) object: the parsed
//! [`BerObject`](ber/struct.BerObject.html), an `Incomplete` value, or an error.
//!
//! Note that this type is also a `Result`, so usual functions (`map`, `unwrap` etc.) are available.
//!
//! # Notes
//!
//! ## BER/DER Integers
//!
//! DER integers can be of any size, so it is not possible to store them as simple integers (they
//! are stored as raw bytes).
//!
//! To get a simple value, use [`BerObject::as_u32`](ber/struct.BerObject.html#method.as_u32)
//! (knowning that this method will return an error if the integer is too large),
//! [`BerObject::as_u64`](ber/struct.BerObject.html#method.as_u64), or use the `bigint` feature of
//! this crate and use [`BerObject::as_bigint`](ber/struct.BerObject.html#method.as_bigint).
//!
//! ```rust
//! use der_parser::ber::*;
//! use der_parser::error::BerResult;
//!
//! let data = &[0x02, 0x03, 0x01, 0x00, 0x01];
//!
//! let (_, object) = parse_ber_integer(data).expect("parsing failed");
//! assert_eq!(object.as_u64(), Ok(65537));
//! ```
//!
//! Access to the raw value is possible using the `as_slice` method.
//!
//! ## Misc Notes
//!
//! - The DER constraints are verified if using `parse_der`.
//! - `BerObject` and `DerObject` are the same objects (type alias). The only difference is the
//!   verification of constraints *during parsing*.
//!
//! # Serialization
//!
//! Support for encoding BER/DER objects is currently being tested and can be used by activating the `serialize` feature.
//! Note that current status is **experimental**.
//!
//! See the `ber_encode_*` functions in the [`ber`](ber/index.html) module, and
//! [`BerObject::to_vec`](ber/struct.BerObject.html#method.to_vec)
//!
//! # References
//!
//! - [[X.680]] Abstract Syntax Notation One (ASN.1): Specification of basic notation.
//! - [[X.690]] ASN.1 encoding rules: Specification of Basic Encoding Rules (BER), Canonical
//!   Encoding Rules (CER) and Distinguished Encoding Rules (DER).
//!
//! [X.680]: http://www.itu.int/rec/T-REC-X.680/en "Abstract Syntax Notation One (ASN.1):
//!   Specification of basic notation."
//! [X.690]: https://www.itu.int/rec/T-REC-X.690/en "ASN.1 encoding rules: Specification of
//!   Basic Encoding Rules (BER), Canonical Encoding Rules (CER) and Distinguished Encoding Rules
//!   (DER)."

#![deny(/*missing_docs,*/
        unstable_features,
        unused_import_braces,
        unused_qualifications,
        unreachable_pub)]
#![forbid(unsafe_code)]
#![warn(
    /* missing_docs,
    rust_2018_idioms,*/
    missing_debug_implementations,
)]
// pragmas for doc
#![deny(intra_doc_link_resolution_failure)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[macro_use]
mod macros;

#[allow(clippy::module_inception)]
pub mod ber;
pub mod der;
pub mod error;
pub mod oid;

// compatibility: re-export at crate root
pub use ber::parse_ber;
pub use der::parse_der;

pub extern crate nom;
#[cfg(feature = "bigint")]
#[cfg_attr(docsrs, doc(cfg(feature = "bigint")))]
pub extern crate num_bigint;

// re-exports nom macros, so this crate's macros can be used without importing nom
#[doc(hidden)]
pub use nom::{alt, call, complete, do_parse, eof, many0, map, map_res, verify, IResult};
#[doc(hidden)]
pub use rusticata_macros::{custom_check, flat_take};

use proc_macro_hack::proc_macro_hack;

#[proc_macro_hack]
/// Procedural macro to get encoded oids, see the [oid module](oid/index.html).
pub use der_oid_macro::oid;
