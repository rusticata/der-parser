use crate::ber::*;
use crate::der::DerObject;
use crate::error::*;
use nom::number::streaming::be_u8;
use nom::*;
use rusticata_macros::custom_check;
use std::convert::TryFrom;

use crate::ber::MAX_RECURSION;

/// Parse DER object recursively
///
/// Return a tuple containing the remaining (unparsed) bytes and the DER Object, or an error.
///
/// *Note: this is the same as calling `parse_der_recursive` with `MAX_RECURSION`.
///
/// ### Example
///
/// ```
/// use der_parser::ber::BerTag;
/// use der_parser::der::parse_der;
///
/// let bytes = &[0x02, 0x03, 0x01, 0x00, 0x01];
/// let (_, obj) = parse_der(bytes).expect("parsing failed");
///
/// assert_eq!(obj.header.tag, BerTag::Integer);
/// ```
#[inline]
pub fn parse_der(i: &[u8]) -> DerResult {
    parse_der_recursive(i, MAX_RECURSION)
}

/// Parse DER object recursively, specifying the maximum recursion depth
///
/// Return a tuple containing the remaining (unparsed) bytes and the DER Object, or an error.
///
/// ### Example
///
/// ```
/// use der_parser::ber::BerTag;
/// use der_parser::der::parse_der_recursive;
///
/// let bytes = &[0x02, 0x03, 0x01, 0x00, 0x01];
/// let (_, obj) = parse_der_recursive(bytes, 1).expect("parsing failed");
///
/// assert_eq!(obj.header.tag, BerTag::Integer);
/// ```
pub fn parse_der_recursive(i: &[u8], max_depth: usize) -> DerResult {
    let (i, hdr) = der_read_element_header(i)?;
    // safety check: length cannot be more than 2^32 bytes
    if let BerSize::Definite(l) = hdr.len {
        custom_check!(i, l > MAX_OBJECT_SIZE, BerError::InvalidLength)?;
    }
    der_read_element_content_recursive(i, hdr, max_depth)
}

#[doc(hidden)]
#[macro_export]
macro_rules! der_constraint_fail_if(
    ($slice:expr, $cond:expr) => (
        {
            if $cond {
                return Err(::nom::Err::Error(BerError::DerConstraintFailed));
            }
        }
    );
);

/// Parse a DER object, expecting a value with specified tag
///
/// The object is parsed recursively, with a maximum depth of `MAX_RECURSION`.
///
/// ### Example
///
/// ```
/// use der_parser::ber::BerTag;
/// use der_parser::der::parse_der_with_tag;
///
/// let bytes = &[0x02, 0x03, 0x01, 0x00, 0x01];
/// let (_, obj) = parse_der_with_tag(bytes, BerTag::Integer).expect("parsing failed");
///
/// assert_eq!(obj.header.tag, BerTag::Integer);
/// ```
pub fn parse_der_with_tag<Tag: Into<BerTag>>(i: &[u8], tag: Tag) -> DerResult {
    let tag = tag.into();
    let (i, hdr) = der_read_element_header(i)?;
    if hdr.tag != tag {
        return Err(nom::Err::Error(BerError::InvalidTag));
    }
    let (i, content) =
        der_read_element_content_as(i, hdr.tag, hdr.len, hdr.is_constructed(), MAX_RECURSION)?;
    Ok((i, BerObject::from_header_and_content(hdr, content)))
}

/// Read end of content marker
#[inline]
pub fn parse_der_endofcontent(i: &[u8]) -> DerResult {
    parse_der_with_tag(i, BerTag::EndOfContent)
}

/// Read a boolean value
///
/// The encoding of a boolean value shall be primitive. The contents octets shall consist of a
/// single octet.
///
/// If the boolean value is FALSE, the octet shall be zero.
/// If the boolean value is TRUE, the octet shall be one byte, and have all bits set to one (0xff).
#[inline]
pub fn parse_der_bool(i: &[u8]) -> DerResult {
    parse_der_with_tag(i, BerTag::Boolean)
}

/// Read an integer value
///
/// The encoding of a boolean value shall be primitive. The contents octets shall consist of one or
/// more octets.
///
/// To access the content, use the [`as_u64`](struct.BerObject.html#method.as_u64),
/// [`as_u32`](struct.BerObject.html#method.as_u32),
/// [`as_biguint`](struct.BerObject.html#method.as_biguint) or
/// [`as_bigint`](struct.BerObject.html#method.as_bigint) methods.
/// Remember that a BER integer has unlimited size, so these methods return `Result` or `Option`
/// objects.
///
/// # Examples
///
/// ```rust
/// # use der_parser::der::{parse_der_integer, DerObject};
/// # use der_parser::ber::BerObjectContent;
/// let empty = &b""[..];
/// let bytes = [0x02, 0x03, 0x01, 0x00, 0x01];
/// let expected  = DerObject::from_obj(BerObjectContent::Integer(b"\x01\x00\x01"));
/// assert_eq!(
///     parse_der_integer(&bytes),
///     Ok((empty, expected))
/// );
/// ```
#[inline]
pub fn parse_der_integer(i: &[u8]) -> DerResult {
    parse_der_with_tag(i, BerTag::Integer)
}

/// Read an bitstring value
#[inline]
pub fn parse_der_bitstring(i: &[u8]) -> DerResult {
    parse_der_with_tag(i, BerTag::BitString)
}

/// Read an octetstring value
#[inline]
pub fn parse_der_octetstring(i: &[u8]) -> DerResult {
    parse_der_with_tag(i, BerTag::OctetString)
}

/// Read a null value
#[inline]
pub fn parse_der_null(i: &[u8]) -> DerResult {
    parse_der_with_tag(i, BerTag::Null)
}

/// Read an object identifier value
#[inline]
pub fn parse_der_oid(i: &[u8]) -> DerResult {
    parse_der_with_tag(i, BerTag::Oid)
}

/// Read an enumerated value
#[inline]
pub fn parse_der_enum(i: &[u8]) -> DerResult {
    parse_der_with_tag(i, BerTag::Enumerated)
}

/// Read a UTF-8 string value. The encoding is checked.
#[inline]
pub fn parse_der_utf8string(i: &[u8]) -> DerResult {
    parse_der_with_tag(i, BerTag::Utf8String)
}

/// Read a relative object identifier value
#[inline]
pub fn parse_der_relative_oid(i: &[u8]) -> DerResult {
    parse_der_with_tag(i, BerTag::RelativeOid)
}

/// Parse a sequence of DER elements
///
/// Read a sequence of DER objects, without any constraint on the types.
/// Sequence is parsed recursively, so if structured elements are found, they are parsed using the
/// same function.
///
/// To read a specific sequence of objects (giving the expected types), use the
/// [`parse_ber_sequence_defined`](macro.parse_ber_sequence_defined.html) macro.
#[inline]
pub fn parse_der_sequence(i: &[u8]) -> DerResult {
    parse_der_with_tag(i, BerTag::Sequence)
}

/// Parse a set of DER elements
///
/// Read a set of DER objects, without any constraint on the types.
/// Set is parsed recursively, so if structured elements are found, they are parsed using the
/// same function.
///
/// To read a specific set of objects (giving the expected types), use the
/// [`parse_ber_set_defined`](macro.parse_ber_set_defined.html) macro.
#[inline]
pub fn parse_der_set(i: &[u8]) -> DerResult {
    parse_der_with_tag(i, BerTag::Set)
}

/// Read a numeric string value. The content is verified to
/// contain only digits and spaces.
#[inline]
pub fn parse_der_numericstring(i: &[u8]) -> DerResult {
    parse_der_with_tag(i, BerTag::NumericString)
}

/// Read a printable string value. The content is verified to
/// contain only the allowed characters.
#[inline]
pub fn parse_der_printablestring(i: &[u8]) -> DerResult {
    parse_der_with_tag(i, BerTag::PrintableString)
}

/// Read a T61 string value
#[inline]
pub fn parse_der_t61string(i: &[u8]) -> DerResult {
    parse_der_with_tag(i, BerTag::T61String)
}

/// Read an IA5 string value. The content is verified to be ASCII.
#[inline]
pub fn parse_der_ia5string(i: &[u8]) -> DerResult {
    parse_der_with_tag(i, BerTag::Ia5String)
}

/// Read an UTC time value
#[inline]
pub fn parse_der_utctime(i: &[u8]) -> DerResult {
    parse_der_with_tag(i, BerTag::UtcTime)
}

/// Read a Generalized time value
#[inline]
pub fn parse_der_generalizedtime(i: &[u8]) -> DerResult {
    parse_der_with_tag(i, BerTag::GeneralizedTime)
}

/// Read a GeneralString value
#[inline]
pub fn parse_der_generalstring(i: &[u8]) -> DerResult {
    parse_der_with_tag(i, BerTag::GeneralString)
}

/// Read a BmpString value
#[inline]
pub fn parse_der_bmpstring(i: &[u8]) -> DerResult {
    parse_der_with_tag(i, BerTag::BmpString)
}

/// Parse an optional tagged object, applying function to get content
///
/// This function returns a `DerObject`, trying to read content as generic DER objects.
/// If parsing failed, return an optional object containing `None`.
///
/// To support other return or error types, use
/// [parse_ber_tagged_explicit_g](fn.parse_ber_tagged_explicit_g.html)
///
/// This function will never fail: if parsing content failed, the BER value `Optional(None)` is
/// returned.
#[inline]
pub fn parse_der_explicit_optional<F>(i: &[u8], tag: BerTag, f: F) -> DerResult
where
    F: Fn(&[u8]) -> DerResult,
{
    parse_ber_explicit_optional(i, tag, f)
}

/// Parse an optional tagged object, applying function to get content
///
/// This function is deprecated, use
/// [parse_der_explicit_optional](fn.parse_der_explicit_optional.html) instead.
#[deprecated(
    since = "5.0",
    note = "Please use `parse_der_explicit_optional` instead"
)]
#[inline]
pub fn parse_der_explicit<F>(i: &[u8], tag: BerTag, f: F) -> BerResult
where
    F: Fn(&[u8]) -> BerResult,
{
    parse_der_explicit_optional(i, tag, f)
}

/// Parse an implicit tagged object, applying function to read content
///
/// Note: unlike explicit tagged functions, the callback must be a *content* parsing function,
/// often based on the [`parse_der_content`](fn.parse_der_content.html) combinator.
///
/// The built object will use the original header (and tag), so the content may not match the tag
/// value.
///
/// For a combinator version, see [parse_ber_tagged_implicit](../ber/fn.parse_ber_tagged_implicit.html).
///
/// For a generic version (different output and error types), see
/// [parse_ber_tagged_implicit_g](../ber/fn.parse_ber_tagged_implicit_g.html).
///
/// # Examples
///
/// The following parses `[3] IMPLICIT INTEGER` into a `DerObject`:
///
/// ```rust
/// # use der_parser::ber::*;
/// # use der_parser::der::*;
/// # use der_parser::error::DerResult;
/// #
/// fn parse_int_implicit(i:&[u8]) -> DerResult {
///     parse_der_implicit(
///         i,
///         3,
///         parse_der_content(BerTag::Integer),
///     )
/// }
///
/// # let bytes = &[0x83, 0x03, 0x01, 0x00, 0x01];
/// let res = parse_int_implicit(bytes);
/// # match res {
/// #     Ok((rem, content)) => {
/// #         assert!(rem.is_empty());
/// #         assert_eq!(content.as_u32(), Ok(0x10001));
/// #     },
/// #     _ => assert!(false)
/// # }
/// ```
#[inline]
pub fn parse_der_implicit<'a, Tag, F>(i: &'a [u8], tag: Tag, f: F) -> DerResult<'a>
where
    F: Fn(&'a [u8], &'_ BerObjectHeader, usize) -> BerResult<'a, BerObjectContent<'a>>,
    Tag: Into<BerTag>,
{
    parse_ber_implicit(i, tag, f)
}

/// Parse DER object and try to decode it as a 32-bits unsigned integer
pub fn parse_der_u32(i: &[u8]) -> BerResult<u32> {
    match parse_ber_integer(i) {
        Ok((rem, ref obj)) => match obj.content {
            BerObjectContent::Integer(i) => match i.len() {
                1 => Ok((rem, u32::from(i[0]))),
                2 => Ok((rem, u32::from(i[0]) << 8 | u32::from(i[1]))),
                3 => Ok((
                    rem,
                    u32::from(i[0]) << 16 | u32::from(i[1]) << 8 | u32::from(i[2]),
                )),
                4 => Ok((
                    rem,
                    u32::from(i[0]) << 24
                        | u32::from(i[1]) << 16
                        | u32::from(i[2]) << 8
                        | u32::from(i[3]),
                )),
                _ => Err(Err::Error(BerError::IntegerTooLarge)),
            },
            _ => Err(Err::Error(BerError::InvalidTag)),
        },
        Err(e) => Err(e),
    }
}

/// Parse DER object and try to decode it as a 64-bits unsigned integer
pub fn parse_der_u64(i: &[u8]) -> BerResult<u64> {
    match parse_ber_integer(i) {
        Ok((rem, ref obj)) => match obj.content {
            BerObjectContent::Integer(i) => match bytes_to_u64(i) {
                Ok(l) => Ok((rem, l)),
                Err(_) => Err(Err::Error(BerError::IntegerTooLarge)),
            },
            _ => Err(Err::Error(BerError::InvalidTag)),
        },
        Err(e) => Err(e),
    }
}

/// Parse the next bytes as the content of a DER object (combinator)
///
/// Content type is *not* checked to match tag, caller is responsible of providing the correct tag
///
/// Caller is also responsible to check if parsing function consumed the expected number of
/// bytes (`header.len`).
///
/// The arguments of the parse function are: `(input, ber_object_header, max_recursion)`.
///
/// Example: manually parsing header and content
///
/// ```
/// # use der_parser::ber::{BerTag, MAX_RECURSION};
/// # use der_parser::der::*;
/// #
/// # let bytes = &[0x02, 0x03, 0x01, 0x00, 0x01];
/// let (i, header) = der_read_element_header(bytes).expect("parsing failed");
/// let (rem, content) = parse_der_content(header.tag)(i, &header, MAX_RECURSION)
///     .expect("parsing failed");
/// #
/// # assert_eq!(header.tag, BerTag::Integer);
/// ```
pub fn parse_der_content<'a>(
    tag: BerTag,
) -> impl Fn(&'a [u8], &'_ BerObjectHeader, usize) -> BerResult<'a, BerObjectContent<'a>> {
    move |i: &[u8], hdr: &BerObjectHeader, max_recursion: usize| {
        der_read_element_content_as(i, tag, hdr.len, hdr.is_constructed(), max_recursion)
    }
}
// --------- end of parse_der_xxx functions ----------

/// Parse the next bytes as the content of a DER object.
///
/// Content type is *not* checked, caller is reponsible of providing the correct tag
pub fn der_read_element_content_as(
    i: &[u8],
    tag: BerTag,
    len: BerSize,
    constructed: bool,
    max_depth: usize,
) -> BerResult<BerObjectContent> {
    if let BerSize::Definite(l) = len {
        if i.len() < l {
            return Err(Err::Incomplete(Needed::Size(l)));
        }
    }
    match tag {
        BerTag::Boolean => {
            let len = len.primitive()?;
            custom_check!(i, len != 1, BerError::InvalidLength)?;
            der_constraint_fail_if!(i, i[0] != 0 && i[0] != 0xff);
        }
        BerTag::BitString => {
            der_constraint_fail_if!(i, constructed);
            let len = len.primitive()?;
            // exception: read and verify padding bits
            return der_read_content_bitstring(i, len);
        }
        BerTag::NumericString
        | BerTag::PrintableString
        | BerTag::Ia5String
        | BerTag::Utf8String
        | BerTag::T61String
        | BerTag::BmpString
        | BerTag::GeneralString => {
            der_constraint_fail_if!(i, constructed);
        }
        BerTag::UtcTime | BerTag::GeneralizedTime => {
            let len = len.primitive()?;
            if len == 0 || i.get(len - 1).cloned() != Some(b'Z') {
                return Err(Err::Error(BerError::DerConstraintFailed));
            }
        }
        _ => (),
    }
    ber_read_element_content_as(i, tag, len, constructed, max_depth)
}

/// Parse DER object content recursively
///
/// *Note: an error is raised if recursion depth exceeds `MAX_RECURSION`.
pub fn der_read_element_content<'a>(i: &'a [u8], hdr: BerObjectHeader<'a>) -> DerResult<'a> {
    der_read_element_content_recursive(i, hdr, MAX_RECURSION)
}

fn der_read_element_content_recursive<'a>(
    i: &'a [u8],
    hdr: BerObjectHeader<'a>,
    max_depth: usize,
) -> DerResult<'a> {
    match hdr.class {
        BerClass::Universal | BerClass::Private => (),
        _ => {
            let (i, content) = ber_get_object_content(i, &hdr)?;
            let content = BerObjectContent::Unknown(hdr.tag, content);
            let obj = BerObject::from_header_and_content(hdr, content);
            return Ok((i, obj));
        }
    }
    match der_read_element_content_as(i, hdr.tag, hdr.len, hdr.is_constructed(), max_depth) {
        Ok((rem, content)) => Ok((rem, DerObject::from_header_and_content(hdr, content))),
        Err(Err::Error(BerError::UnknownTag)) => {
            let (rem, content) = ber_get_object_content(i, &hdr)?;
            let content = BerObjectContent::Unknown(hdr.tag, content);
            let obj = BerObject::from_header_and_content(hdr, content);
            Ok((rem, obj))
        }
        Err(e) => Err(e),
    }
}

fn der_read_content_bitstring(i: &[u8], len: usize) -> BerResult<BerObjectContent> {
    do_parse! {
        i,
        ignored_bits: be_u8 >>
                      custom_check!(ignored_bits > 7, BerError::DerConstraintFailed) >>
                      custom_check!(len == 0, BerError::InvalidLength) >>
        s:            take!(len - 1) >>
                      call!(|input| {
                          if len > 1 {
                              let mut last_byte = s[len-2];
                              for _ in 0..ignored_bits as usize {
                                  der_constraint_fail_if!(i, last_byte & 1 != 0);
                                  last_byte >>= 1;
                              }
                          }
                          Ok((input,()))
                      }) >>
        ( BerObjectContent::BitString(ignored_bits,BitStringObject{ data:s }) )
    }
}

/// Read an object header (DER)
pub fn der_read_element_header(i: &[u8]) -> BerResult<BerObjectHeader> {
    do_parse! {
        i,
        el:   parse_identifier >>
        len:  parse_ber_length_byte >>
        llen: cond!(len.0 == 1, take!(len.1)) >>
        ( {
            let class = match BerClass::try_from(el.0) {
                Ok(c) => c,
                Err(_) => unreachable!(), // Cannot fail, we read only 2 bits
            };
            let len : usize = match len.0 {
                0 => usize::from(len.1),
                _ => {
                    // if len is 0xff -> error (8.1.3.5)
                    custom_check!(&i[1..], len.1 == 0b0111_1111, BerError::InvalidLength)?;
                    // if len.1 == 0b0111_1111 {
                    //     return Err(::nom::Err::Error(error_position!(&i[1..], ErrorKind::Custom(BER_INVALID_LENGTH))));
                    // }
                    // DER(9.1) if len is 0 (indefinite form), obj must be constructed
                    der_constraint_fail_if!(&i[1..], len.1 == 0 && el.1 != 1);
                    // if len.1 == 0 && el.1 != 1 {
                    //     return Err(::nom::Err::Error(error_position!(&i[1..], ErrorKind::Custom(BER_INVALID_LENGTH))));
                    // }
                    let llen = llen.unwrap(); // safe because we tested len.0 != 0
                    match bytes_to_u64(llen) {
                        Ok(l)  => {
                            // DER: should have been encoded in short form (< 127)
                            der_constraint_fail_if!(i, l < 127);
                            usize::try_from(l).or(Err(nom::Err::Error(BerError::InvalidLength)))?
                        },
                        Err(_) => { return Err(::nom::Err::Error(BerError::InvalidTag)); },
                    }
                },
            };
            BerObjectHeader::new(class, el.1, BerTag(el.2), len).with_raw_tag(Some(el.3))
        } )
    }
}
