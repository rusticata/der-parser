<!-- cargo-sync-readme start -->

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
[![docs.rs](https://docs.rs/der-parser/badge.svg)](https://docs.rs/der-parser)
[![crates.io](https://img.shields.io/crates/v/der-parser.svg)](https://crates.io/crates/der-parser)
[![Download numbers](https://img.shields.io/crates/d/der-parser.svg)](https://crates.io/crates/der-parser)
[![Travis CI](https://travis-ci.org/rusticata/der-parser.svg?branch=master)](https://travis-ci.org/rusticata/der-parser)
[![AppVeyor CI](https://ci.appveyor.com/api/projects/status/github/rusticata/der-parser?svg=true)](https://ci.appveyor.com/project/chifflier/der-parser)
[![dependency status](https://deps.rs/crate/der-parser/4.0.2/status.svg)](https://deps.rs/crate/der-parser/4.0.2)

# BER/DER Parser

A parser for Basic Encoding Rules (BER [[X.690]]) and Distinguished Encoding Rules(DER
[[X.690]]), implemented with the [nom](https://github.com/Geal/nom) parser combinator
framework.

It is written in pure Rust, fast, and makes extensive use of zero-copy. A lot of care is taken
to ensure security and safety of this crate, including design (recursion limit, defensive
programming), tests, and fuzzing. It also aims to be panic-free.

The code is available on [Github](https://github.com/rusticata/der-parser)
and is part of the [Rusticata](https://github.com/rusticata) project.

# DER parser design

There are two different approaches for parsing DER objects: reading the objects recursively as
long as the tags are known, or specifying a description of the expected objects (generally from
the [ASN.1][X.680] description).

The first parsing method can be done using the [`parse_ber`](https://docs.rs/der-parser/latest/der_parser/ber/fn.parse_ber.html) and
[`parse_der`](https://docs.rs/der-parser/latest/der_parser/der/fn.parse_der.html) methods.
It is useful when decoding an arbitrary DER object.
However, it cannot fully parse all objects, especially those containing IMPLICIT, OPTIONAL, or
DEFINED BY items.

```rust
use der_parser::parse_der;

let bytes = [ 0x30, 0x0a,
              0x02, 0x03, 0x01, 0x00, 0x01,
              0x02, 0x03, 0x01, 0x00, 0x00,
];

let parsed = parse_der(&bytes);
```

The second (and preferred) parsing method is to specify the expected objects recursively. The
following macros can be used:
[`parse_der_sequence_defined`](https://docs.rs/der-parser/latest/der_parser/macro.parse_der_sequence_defined.html) and similar functions,
[`parse_der_struct`](https://docs.rs/der-parser/latest/der_parser/macro.parse_der_struct.html), etc.

For example, to read a sequence containing two integers:

```rust
use der_parser::ber::*;
use der_parser::error::BerResult;

fn localparse_seq(i:&[u8]) -> BerResult {
    parse_der_sequence_defined!(i,
        parse_ber_integer >>
        parse_ber_integer
    )
}

let bytes = [ 0x30, 0x0a,
              0x02, 0x03, 0x01, 0x00, 0x01,
              0x02, 0x03, 0x01, 0x00, 0x00,
];
let parsed = localparse_seq(&bytes);
```

All functions return a [`BerResult`](https://docs.rs/der-parser/latest/der_parser/error/type.BerResult.html) object: the parsed
[`BerObject`](https://docs.rs/der-parser/latest/der_parser/ber/struct.BerObject.html), an `Incomplete` value, or an error.

Note that this type is also a `Result`, so usual functions (`map`, `unwrap` etc.) are available.

# Notes

## BER/DER Integers

DER integers can be of any size, so it is not possible to store them as simple integers (they
are stored as raw bytes).

To get a simple value, use [`BerObject::as_u32`](ber/struct.BerObject.html#method.as_u32)
(knowning that this method will return an error if the integer is too large),
[`BerObject::as_u64`](ber/struct.BerObject.html#method.as_u64), or use the `bigint` feature of
this crate and use [`BerObject::as_bigint`](https://docs.rs/der-parser/latest/der_parser/ber/struct.BerObject.html#method.as_bigint).

```rust
use der_parser::ber::*;
use der_parser::error::BerResult;

let data = &[0x02, 0x03, 0x01, 0x00, 0x01];

let (_, object) = parse_ber_integer(data).expect("parsing failed");
assert_eq!(object.as_u64(), Ok(65537));
```

Access to the raw value is possible using the `as_slice` method.

## Misc Notes

- The DER constraints are verified if using `parse_der`.
- `BerObject` and `DerObject` are the same objects (type alias). The only difference is the
  verification of constraints *during parsing*.

# Serialization

Support for encoding BER/DER objects is currently being tested and can be used by activating the `serialize` feature.
Note that current status is **experimental**.

See the `ber_encode_*` functions in the [`ber`](https://docs.rs/der-parser/latest/der_parser/ber/index.html) module, and
[`BerObject::to_vec`](https://docs.rs/der-parser/latest/der_parser/ber/struct.BerObject.html#method.to_vec)

# References

- [[X.680]] Abstract Syntax Notation One (ASN.1): Specification of basic notation.
- [[X.690]] ASN.1 encoding rules: Specification of Basic Encoding Rules (BER), Canonical
  Encoding Rules (CER) and Distinguished Encoding Rules (DER).

[X.680]: http://www.itu.int/rec/T-REC-X.680/en "Abstract Syntax Notation One (ASN.1):
  Specification of basic notation."
[X.690]: https://www.itu.int/rec/T-REC-X.690/en "ASN.1 encoding rules: Specification of
  Basic Encoding Rules (BER), Canonical Encoding Rules (CER) and Distinguished Encoding Rules
  (DER)."
<!-- cargo-sync-readme end -->

## Changes

See `CHANGELOG.md`, and `UPGRADING.md` for instructions for upgrading major versions.

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
