# Change Log

## [Unreleased][unreleased]

### Thanks

### Added

## 4.1.0

### Added/Changed

- Re-export num-bigint so crate users do not have to import it
- Add function versions to parse BER sequences/sets (#20)
- Add function versions to parse BER tagged objects (#20)
- Add generic error type to structured parsing functions
- Add function to parse a generic BER container object
- Document that trailing bytes from SEQUENCE/SET are ignored
- Deprecate functions `parse_{ber,der}_explicit` (use `_optional`)

## 4.0.2

### Changed/Fixed

- Upgrade dependencies on num-bigint and der-oid-macro

## 4.0.1

### Changed/Fixed

- Add workaround to fix parsing of empty sequence or set

## 4.0.0

**Attention** This is a major release, with several API-breaking changes. See `UPGRADING.md` for instructions.

### Thanks

- Jannik Schürg (oid, string verifications)

### Added

- Add functions `parse_ber_recursive` and `parse_der_recursive`, allowing to specify maximum 
  recursion depth when parsing
- The string types `IA5String`, `NumericString`, `PrintableString` and `UTF8String`
  do now only parse if the characters are valid.
- `as_str()` was added to `BerObjectContent` to obtain a `&str` for the types above.
  `as_slice()` works as before.
- Implement `Error` trait for `BerError`
- Add method to extract raw tag from header
  - `BerObjectHeader` now has a lifetime and a `raw_tag` field
  - `BerObject` now has a `raw_tag` field
  - Implement `PartialEq` manually for `BerObject`: `raw_tag` is compared only if both fields provide it
- Add type `BerClass`
- Start adding serialization support (experimental) using the `serialize` feature

### Changed/Fixed

- Make header part of `BerObject`, remove duplicate fields
- Maximum recursion logic has changed. Instead of providing the current depth, the argument is
  now the maximum possible depth.
- Change the api around `Oid` to achieve zero-copy. The following changed:
  - The `Oid` struct now has a lifetime and uses `Cow` internally.
  - The procedural macro `oid!` was added.
  - `Oid::from` returns a `Result` now.
  - The `Oid` struct now encodes whether the oid is relative or not.
  - The `Debug` implementation now shows whether the oid is relative
    and uses the bigint feature if available.
  - The `Oid::iter` method now returns an `Option`. `Oid::iter_bigint` was
    added.
  - `Hash` is now derived for `Oid`.
- Minimum rust version is now 1.34

## 3.0.3

- Make the pretty-printer function public
- Fix DER datestring sanity check
- CI
  - add rusfmt check
  - add cargo clippy

## 3.0.2

- Add `parse_ber_u32` and `parse_ber_u64` functions
- Fix typo in description

## 3.0.1

- Add crate `BerResult` and `DerResult` types
- Use crate result types, remove uneeded imports
  - Crates using `der-parser` do not need to import `nom` or `rusticata-macros` anymore
  - Result types are aliases, so API is unchanged

## 3.0.0

- Upgrade to nom 5 (breaks API)
- New error types, now all functions use `BerError`

## 2.1.0

- Handle BER/DER tags that are longer than one byte.
- Set edition to 2018

## 2.0.2

- Revert 2.0.1 release, breaks API

## 2.0.1

- Handle BER/DER tags that are longer than one byte.

## 2.0.0

- Refactor code, split BER and DER, check DER constraints
- Add recursion limit for sequences and sets
- Rustfmt
- Documentation
- Remove unused function `ber_read_element_content`

## 1.1.1

- Fix OID parsing, and add support for relative OIDs
- Add FromStr trait for Oid

## 1.1.0

- Use num-bigint over num and upgrade to 0.2

## 1.0.0

- Upgrade to nom 4

## 0.5.5

- Add functions `parse_der_u32` and `parse_der_u64` to quickly parse integers
- Remove `Oid::from_vec`, `Oid::from` does the same
- Enforce constraints on DER booleans

## 0.5.4

- Add `BitStringObject` to wrap BitString objects
- Mark constructed BitStrings as unsupported
- Do not try to parse application-specific data in `parse_der`

## 0.5.3

- Add function `DerObject::as_u64`
- Add function `DerObject::as_oid_val`
- Add `parse_der_struct!` variant to check tag

## 0.5.2

- Add functions to test object class and primitive/constructed state
- Add macro `parse_der_application!`
- Add macro `parse_der_tagged!` to parse `[x] EXPLICIT` or `[x] IMPLICIT` tagged values

## 0.5.1

- Add type GeneralString
- Add macro `parse_der_struct!`

## 0.5.0

- Allow use of crate without extra use statements
- Use constants for u32 errors instead of magical numbers
- Rename `tag_of_der_content()` to `DerObjectContent::tag`
- Rename DerElementxxx structs to have a consistent naming scheme
- Add documentation for parsing DER sequences and sets, and fix wrong return type for sets
- Fix a lot of clippy warnings
- QA: add pragma rules (disable unsafe code, unstable features etc.)
- More documentation
- Switch license to MIT + APLv2

## 0.4.4

- Add macro parse_der_defined_m, to parse a defined sequence or set
  This macro differs from `parse_der_defined` because it allows using macros
- Rename `DerObject::new_int` to `DerObject::from_int_slice`
- Rename `Oid::to_hex` to `Oid::to_string`
- Document more functions

## 0.4.1

- Add new feature 'bigint' to export DER integers
- OID is now a specific type
- Add new types T61String and BmpString
- Fix wrong expected tag in parse_der_set_of

## 0.4.0

- Der Integers are now represented as slices (byte arrays) since they can be larger than u64.
