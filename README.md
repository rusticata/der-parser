# der-parser

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
[![Build Status](https://travis-ci.org/rusticata/der-parser.svg?branch=master)](https://travis-ci.org/rusticata/der-parser)
[![Crates.io Version](https://img.shields.io/crates/v/der-parser.svg)](https://crates.io/crates/der-parser)

## Overview

der-parser is a parser for the DER protocol.

## Important

*This parser is still experimental and very incomplete*

## Changes

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
