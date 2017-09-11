# der-parser

[![LICENSE](https://img.shields.io/badge/License-LGPL%20v2.1-blue.svg)](LICENSE)
[![Build Status](https://travis-ci.org/rusticata/der-parser.svg?branch=master)](https://travis-ci.org/rusticata/der-parser)
[![Crates.io Version](https://img.shields.io/crates/v/der-parser.svg)](https://crates.io/crates/der-parser)

## Overview

der-parser is a parser for the DER protocol.

## Important

*This parser is still experimental and very incomplete*

## Changes

### 0.4.1

- Add new feature 'bigint' to export DER integers
- OID is now a specific type
- Add new types T61String and BmpString
- Fix wrong expected tag in parse_der_set_of

### 0.4.0

- Der Integers are now represented as slices (byte arrays) since they can be larger than u64.

## License

This library is licensed under the GNU Lesser General Public License version 2.1, or (at your option) any later version.
