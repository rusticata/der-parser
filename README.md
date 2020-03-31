# der-parser

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
[![Build Status](https://travis-ci.org/rusticata/der-parser.svg?branch=master)](https://travis-ci.org/rusticata/der-parser)
[![Crates.io Version](https://img.shields.io/crates/v/der-parser.svg)](https://crates.io/crates/der-parser)

<!-- cargo-sync-readme start -->

# BER/DER Parser

A parser for Basic Encoding Rules (BER [[X.690]]) and Distinguished Encoding Rules(DER
[[X.690]]), implemented with the [nom](https://github.com/Geal/nom) parser combinator
framework.

The code is available on [Github](https://github.com/rusticata/der-parser)
and is part of the [Rusticata](https://github.com/rusticata) project.

# DER parser design

There are two different approaches for parsing DER objects: reading the objects recursively as
long as the tags are known, or specifying a description of the expected objects (generally from
the [ASN.1][X.680] description).

The first parsing method can be done using the [`parse_ber`](ber/fn.parse_ber.html) and
[`parse_der`](der/fn.parse_der.html) methods.
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
[`parse_der_sequence_defined`](macro.parse_der_sequence_defined.html) and similar functions,
[`parse_der_struct`](macro.parse_der_struct.html), etc.

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

All functions return a [`BerResult`](error/type.BerResult.html) object: the parsed
[`BerObject`](ber/struct.BerObject.html), an `Incomplete` value, or an error.

Note that this type is also a `Result`, so usual functions (`map`, `unwrap` etc.) are available.

# Notes

- The DER constraints are verified if using `parse_der`.
- `BerObject` and `DerObject` are the same objects (type alias). The only difference is the
  verification of constraints *during parsing*.
- DER integers can be of any size, so it is not possible to store them as simple integers (they
are stored as raw bytes). To get a simple value, use
[`BerObject::as_u32`](ber/struct.BerObject.html#method.as_u32) (knowning that this method will
return an error if the integer is too large), [`BerObject::as_u64`](ber/struct.BerObject.html#method.as_u64),
or use the `bigint` feature of this crate and use
[`BerObject::as_bigint`](ber/struct.BerObject.html#method.as_bigint).

# Serialization

Support for encoding BER/DER objects is currently being tested and can be used by activating the `serialize` feature.
Note that current status is **experimental**.

See the `ber_encode_*` functions in the [`ber`](ber/index.html) module, and [`BerObject::to_vec`](ber/struct.BerObject.html#method.to_vec)

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

See `CHANGELOG.md`

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
