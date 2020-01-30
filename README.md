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

### 3.0.4

- Use cloned instead of copied to support older rust compiler (1.33)
- Fix new clippy warnings (rust 1.40)

### 3.0.3

- Make the pretty-printer function public
- Fix DER datestring sanity check
- CI
  - add rusfmt check
  - add cargo clippy

### 3.0.2

- Add `parse_ber_u32` and `parse_ber_u64` functions
- Fix typo in description

### 3.0.1

- Add crate `BerResult` and `DerResult` types
- Use crate result types, remove uneeded imports
  - Crates using `der-parser` do not need to import `nom` or `rusticata-macros` anymore
  - Result types are aliases, so API is unchanged

### 3.0.0

- Upgrade to nom 5 (breaks API)
- New error types, now all functions use `BerError`

### 2.1.0

- Handle BER/DER tags that are longer than one byte.
- Set edition to 2018

### 2.0.2

- Revert 2.0.1 release, breaks API

### 2.0.1

- Handle BER/DER tags that are longer than one byte.

### 2.0.0

- Refactor code, split BER and DER, check DER constraints
- Add recursion limit for sequences and sets
- Rustfmt
- Documentation
- Remove unused function `ber_read_element_content`

### 1.1.1

- Fix OID parsing, and add support for relative OIDs
- Add FromStr trait for Oid

### 1.1.0

- Use num-bigint over num and upgrade to 0.2

### 1.0.0

- Upgrade to nom 4

### 0.5.5

- Add functions `parse_der_u32` and `parse_der_u64` to quickly parse integers
- Remove `Oid::from_vec`, `Oid::from` does the same
- Enforce constraints on DER booleans

### 0.5.4

- Add `BitStringObject` to wrap BitString objects
- Mark constructed BitStrings as unsupported
- Do not try to parse application-specific data in `parse_der`

### 0.5.3

- Add function `DerObject::as_u64`
- Add function `DerObject::as_oid_val`
- Add `parse_der_struct!` variant to check tag

### 0.5.2

- Add functions to test object class and primitive/constructed state
- Add macro `parse_der_application!`
- Add macro `parse_der_tagged!` to parse `[x] EXPLICIT` or `[x] IMPLICIT` tagged values

### 0.5.1

- Add type GeneralString
- Add macro `parse_der_struct!`

### 0.5.0

- Allow use of crate without extra use statements
- Use constants for u32 errors instead of magical numbers
- Rename `tag_of_der_content()` to `DerObjectContent::tag`
- Rename DerElementxxx structs to have a consistent naming scheme
- Add documentation for parsing DER sequences and sets, and fix wrong return type for sets
- Fix a lot of clippy warnings
- QA: add pragma rules (disable unsafe code, unstable features etc.)
- More documentation
- Switch license to MIT + APLv2

### 0.4.4

- Add macro parse_der_defined_m, to parse a defined sequence or set
  This macro differs from `parse_der_defined` because it allows using macros
- Rename `DerObject::new_int` to `DerObject::from_int_slice`
- Rename `Oid::to_hex` to `Oid::to_string`
- Document more functions

### 0.4.1

- Add new feature 'bigint' to export DER integers
- OID is now a specific type
- Add new types T61String and BmpString
- Fix wrong expected tag in parse_der_set_of

### 0.4.0

- Der Integers are now represented as slices (byte arrays) since they can be larger than u64.

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
