use crate::ber::*;
use crate::error::*;
use crate::oid::*;
use nom::bytes::streaming::take;
use nom::combinator::{map, map_res, verify};
use nom::number::streaming::be_u8;
use nom::*;
use rusticata_macros::{custom_check, flat_take, parse_hex_to_u64};
use std::borrow::Cow;
use std::convert::TryFrom;

/// Default maximum recursion limit
pub const MAX_RECURSION: usize = 50;

/// Try to parse input bytes as u64
#[inline]
pub(crate) fn bytes_to_u64(s: &[u8]) -> Result<u64, BerError> {
    let mut u: u64 = 0;
    for &c in s {
        if u & 0xff00_0000_0000_0000 != 0 {
            return Err(BerError::IntegerTooLarge);
        }
        u <<= 8;
        u |= u64::from(c);
    }
    Ok(u)
}

pub(crate) fn parse_identifier(i: &[u8]) -> BerResult<(u8, u8, u32, &[u8])> {
    if i.is_empty() {
        Err(Err::Incomplete(Needed::Size(1)))
    } else {
        let a = i[0] >> 6;
        let b = if i[0] & 0b0010_0000 != 0 { 1 } else { 0 };
        let mut c = u32::from(i[0] & 0b0001_1111);

        let mut tag_byte_count = 1;

        if c == 0x1f {
            c = 0;
            loop {
                // Make sure we don't read past the end of our data.
                custom_check!(i, tag_byte_count >= i.len(), BerError::InvalidTag)?;

                // With tag defined as u32 the most we can fit in is four tag bytes.
                // (X.690 doesn't actually specify maximum tag width.)
                custom_check!(i, tag_byte_count > 5, BerError::InvalidTag)?;

                c = (c << 7) | (u32::from(i[tag_byte_count]) & 0x7f);
                let done = i[tag_byte_count] & 0x80 == 0;
                tag_byte_count += 1;
                if done {
                    break;
                }
            }
        }

        let (raw_tag, rem) = i.split_at(tag_byte_count);

        Ok((rem, (a, b, c, raw_tag)))
    }
}

pub(crate) fn parse_ber_length_byte(i: &[u8]) -> BerResult<(u8, u8)> {
    if i.is_empty() {
        Err(Err::Incomplete(Needed::Size(1)))
    } else {
        let a = i[0] >> 7;
        let b = i[0] & 0b0111_1111;
        Ok((&i[1..], (a, b)))
    }
}

/// Read an object header
pub fn ber_read_element_header(i: &[u8]) -> BerResult<BerObjectHeader> {
    let (i1, el) = parse_identifier(i)?;
    let class = match BerClass::try_from(el.0) {
        Ok(c) => c,
        Err(_) => unreachable!(), // Cannot fail, we read only 2 bits
    };
    let (i2, len) = parse_ber_length_byte(i1)?;
    let (i3, len) = match len.0 {
        0 => (i2, u64::from(len.1)),
        _ => {
            // if len is 0xff -> error (8.1.3.5)
            if len.1 == 0b0111_1111 {
                return Err(::nom::Err::Error(BerError::InvalidTag));
            }
            let (i3, llen) = take(len.1)(i2)?;
            // XXX llen: test if 0 (indefinite form), if len is 0xff -> error
            match bytes_to_u64(llen) {
                Ok(l) => (i3, l),
                Err(_) => {
                    return Err(::nom::Err::Error(BerError::InvalidTag));
                }
            }
        }
    };
    let hdr = BerObjectHeader::new(class, el.1, BerTag(el.2), len).with_raw_tag(Some(el.3));
    Ok((i3, hdr))
}

#[inline]
fn ber_read_content_eoc(i: &[u8]) -> BerResult<BerObjectContent> {
    Ok((i, BerObjectContent::EndOfContent))
}

#[inline]
fn ber_read_content_bool(i: &[u8]) -> BerResult<BerObjectContent> {
    match be_u8(i) {
        Ok((rem, 0)) => Ok((rem, BerObjectContent::Boolean(false))),
        Ok((rem, _)) => Ok((rem, BerObjectContent::Boolean(true))),
        Err(e) => Err(e),
    }
}

#[inline]
fn ber_read_content_integer(i: &[u8], len: usize) -> BerResult<BerObjectContent> {
    map(take(len), BerObjectContent::Integer)(i)
}

#[inline]
fn ber_read_content_bitstring(i: &[u8], len: usize) -> BerResult<BerObjectContent> {
    custom_check!(i, len == 0, BerError::InvalidLength)?;

    let (i, ignored_bits) = be_u8(i)?;
    let (i, data) = take(len - 1)(i)?;
    Ok((
        i,
        BerObjectContent::BitString(ignored_bits, BitStringObject { data }),
    ))
}

#[inline]
fn ber_read_content_octetstring(i: &[u8], len: usize) -> BerResult<BerObjectContent> {
    map(take(len), BerObjectContent::OctetString)(i)
}

#[inline]
fn ber_read_content_null(i: &[u8]) -> BerResult<BerObjectContent> {
    Ok((i, BerObjectContent::Null))
}

fn ber_read_content_oid(i: &[u8], len: usize) -> BerResult<BerObjectContent> {
    custom_check!(i, len == 0, BerError::InvalidLength)?;

    let (i1, oid) = verify(take(len), |os: &[u8]| os.last().unwrap() >> 7 == 0u8)(i)?;

    let obj = BerObjectContent::OID(Oid::new(Cow::Borrowed(oid)));
    Ok((i1, obj))
}

#[inline]
fn ber_read_content_enum(i: &[u8], len: usize) -> BerResult<BerObjectContent> {
    parse_hex_to_u64!(i, len).map(|(rem, i)| (rem, BerObjectContent::Enum(i)))
}

fn ber_read_content_utf8string(i: &[u8], len: usize) -> BerResult<BerObjectContent> {
    map_res(take(len), |bytes| {
        std::str::from_utf8(bytes)
            .map(|s| BerObjectContent::UTF8String(s))
            .map_err(|_| BerError::BerValueError)
    })(i)
}

fn ber_read_content_relativeoid(i: &[u8], len: usize) -> BerResult<BerObjectContent> {
    custom_check!(i, len == 0, BerError::InvalidLength)?;

    let (i1, oid) = verify(take(len), |os: &[u8]| os.last().unwrap() >> 7 == 0u8)(i)?;

    let obj = BerObjectContent::RelativeOID(Oid::new_relative(Cow::Borrowed(oid)));
    Ok((i1, obj))
}

fn ber_read_content_sequence(
    i: &[u8],
    len: usize,
    max_depth: usize,
) -> BerResult<BerObjectContent> {
    custom_check!(i, max_depth == 0, BerError::BerMaxDepth)?;
    if len == 0 {
        if i.is_empty() {
            return Ok((i, BerObjectContent::Sequence(Vec::new())));
        }
        // indefinite form
        // read until end-of-content
        map!(
            i,
            many_till!(
                call!(parse_ber_recursive, max_depth - 1),
                parse_ber_endofcontent
            ),
            |(l, _)| { BerObjectContent::Sequence(l) }
        )
    } else {
        map!(
            i,
            flat_take!(
                len,
                many0!(complete!(call!(parse_ber_recursive, max_depth - 1)))
            ),
            |l| { BerObjectContent::Sequence(l) }
        )
    }
}

fn ber_read_content_set(i: &[u8], len: usize, max_depth: usize) -> BerResult<BerObjectContent> {
    custom_check!(i, max_depth == 0, BerError::BerMaxDepth)?;
    if len == 0 {
        if i.is_empty() {
            return Ok((i, BerObjectContent::Set(Vec::new())));
        }
        // indefinite form
        // read until end-of-content
        map!(
            i,
            many_till!(
                call!(parse_ber_recursive, max_depth - 1),
                parse_ber_endofcontent
            ),
            |(l, _)| { BerObjectContent::Set(l) }
        )
    } else {
        map!(
            i,
            flat_take!(
                len,
                many0!(complete!(call!(parse_ber_recursive, max_depth - 1)))
            ),
            |l| { BerObjectContent::Set(l) }
        )
    }
}

fn ber_read_content_numericstring<'a>(i: &'a [u8], len: usize) -> BerResult<BerObjectContent<'a>> {
    // Argument must be a reference, because of the .iter().all(F) call below
    #[allow(clippy::trivially_copy_pass_by_ref)]
    fn is_numeric(b: &u8) -> bool {
        match *b {
            b'0'..=b'9' | b' ' => true,
            _ => false,
        }
    }
    map_res!(i, take!(len), |bytes: &'a [u8]| {
        if !bytes.iter().all(is_numeric) {
            return Err(BerError::BerValueError);
        }
        std::str::from_utf8(bytes)
            .map_err(|_| BerError::BerValueError)
            .map(|s| BerObjectContent::NumericString(s))
    })
}

fn ber_read_content_printablestring<'a>(
    i: &'a [u8],
    len: usize,
) -> BerResult<BerObjectContent<'a>> {
    // Argument must be a reference, because of the .iter().all(F) call below
    #[allow(clippy::trivially_copy_pass_by_ref)]
    fn is_printable(b: &u8) -> bool {
        match *b {
            b'a'..=b'z'
            | b'A'..=b'Z'
            | b'0'..=b'9'
            | b' '
            | b'\''
            | b'('
            | b')'
            | b'+'
            | b','
            | b'-'
            | b'.'
            | b'/'
            | b':'
            | b'='
            | b'?' => true,
            _ => false,
        }
    }
    map_res!(i, take!(len), |bytes: &'a [u8]| {
        if !bytes.iter().all(is_printable) {
            return Err(BerError::BerValueError);
        }
        std::str::from_utf8(bytes)
            .map(|s| BerObjectContent::PrintableString(s))
            .map_err(|_| BerError::BerValueError)
    })
}

#[inline]
fn ber_read_content_t61string(i: &[u8], len: usize) -> BerResult<BerObjectContent> {
    map(take(len), BerObjectContent::T61String)(i)
}

fn ber_read_content_ia5string<'a>(i: &'a [u8], len: usize) -> BerResult<BerObjectContent<'a>> {
    map_res(take(len), |bytes: &'a [u8]| {
        if !bytes.iter().all(u8::is_ascii) {
            return Err(BerError::BerValueError);
        }
        std::str::from_utf8(bytes)
            .map(BerObjectContent::IA5String)
            .map_err(|_| BerError::BerValueError)
    })(i)
}

#[inline]
fn ber_read_content_utctime(i: &[u8], len: usize) -> BerResult<BerObjectContent> {
    map(take(len), BerObjectContent::UTCTime)(i)
}

#[inline]
fn ber_read_content_generalizedtime(i: &[u8], len: usize) -> BerResult<BerObjectContent> {
    map(take(len), BerObjectContent::GeneralizedTime)(i)
}

#[inline]
fn ber_read_content_generalstring(i: &[u8], len: usize) -> BerResult<BerObjectContent> {
    map(take(len), BerObjectContent::GeneralString)(i)
}

#[inline]
fn ber_read_content_bmpstring(i: &[u8], len: usize) -> BerResult<BerObjectContent> {
    map(take(len), BerObjectContent::BmpString)(i)
}

/// Parse the next bytes as the content of a BER object.
///
/// Content type is *not* checked, caller is reponsible of providing the correct tag
pub fn ber_read_element_content_as(
    i: &[u8],
    tag: BerTag,
    len: usize,
    constructed: bool,
    max_depth: usize,
) -> BerResult<BerObjectContent> {
    if i.len() < len {
        return Err(Err::Incomplete(Needed::Size(len)));
    }
    match tag {
        // 0x00 end-of-content
        BerTag::EndOfContent => {
            custom_check!(i, len != 0, BerError::InvalidLength)?;
            ber_read_content_eoc(i)
        }
        // 0x01 bool
        BerTag::Boolean => {
            custom_check!(i, len != 1, BerError::InvalidLength)?;
            ber_read_content_bool(i)
        }
        // 0x02
        BerTag::Integer => {
            custom_check!(i, constructed, BerError::ConstructUnexpected)?;
            ber_read_content_integer(i, len)
        }
        // 0x03: bitstring
        BerTag::BitString => {
            custom_check!(i, constructed, BerError::Unsupported)?; // XXX valid in BER (8.6.3)
            ber_read_content_bitstring(i, len)
        }
        // 0x04: octetstring
        BerTag::OctetString => {
            custom_check!(i, constructed, BerError::Unsupported)?; // XXX valid in BER (8.7.1)
            ber_read_content_octetstring(i, len)
        }
        // 0x05: null
        BerTag::Null => {
            custom_check!(i, constructed, BerError::ConstructUnexpected)?;
            custom_check!(i, len != 0, BerError::InvalidLength)?;
            ber_read_content_null(i)
        }
        // 0x06: object identified
        BerTag::Oid => {
            custom_check!(i, constructed, BerError::ConstructUnexpected)?; // forbidden in 8.19.1
            ber_read_content_oid(i, len)
        }
        // 0x0a: enumerated
        BerTag::Enumerated => {
            custom_check!(i, constructed, BerError::ConstructUnexpected)?; // forbidden in 8.4
            ber_read_content_enum(i, len)
        }
        // 0x0c: UTF8String
        BerTag::Utf8String => {
            custom_check!(i, constructed, BerError::Unsupported)?; // XXX valid in BER (8.21)
            ber_read_content_utf8string(i, len)
        }
        // 0x0d: relative object identified
        BerTag::RelativeOid => {
            custom_check!(i, constructed, BerError::ConstructUnexpected)?;
            ber_read_content_relativeoid(i, len)
        }
        // 0x10: sequence
        BerTag::Sequence => {
            custom_check!(i, !constructed, BerError::ConstructExpected)?;
            ber_read_content_sequence(i, len, max_depth)
        }
        // 0x11: set
        BerTag::Set => {
            custom_check!(i, !constructed, BerError::ConstructExpected)?;
            ber_read_content_set(i, len, max_depth)
        }
        // 0x12: numericstring
        BerTag::NumericString => {
            custom_check!(i, constructed, BerError::Unsupported)?; // XXX valid in BER (8.21)
            ber_read_content_numericstring(i, len)
        }
        // 0x13: printablestring
        BerTag::PrintableString => {
            custom_check!(i, constructed, BerError::Unsupported)?; // XXX valid in BER (8.21)
            ber_read_content_printablestring(i, len)
        }
        // 0x14: t61string
        BerTag::T61String => {
            custom_check!(i, constructed, BerError::Unsupported)?; // XXX valid in BER (8.21)
            ber_read_content_t61string(i, len)
        }
        // 0x16: ia5string
        BerTag::Ia5String => {
            custom_check!(i, constructed, BerError::Unsupported)?; // XXX valid in BER (8.21)
            ber_read_content_ia5string(i, len)
        }
        // 0x17: utctime
        BerTag::UtcTime => ber_read_content_utctime(i, len),
        // 0x18: generalizedtime
        BerTag::GeneralizedTime => ber_read_content_generalizedtime(i, len),
        // 0x1b: generalstring
        BerTag::GeneralString => {
            custom_check!(i, constructed, BerError::Unsupported)?; // XXX valid in BER (8.21)
            ber_read_content_generalstring(i, len)
        }
        // 0x1e: bmpstring
        BerTag::BmpString => {
            custom_check!(i, constructed, BerError::Unsupported)?; // XXX valid in BER (8.21)
            ber_read_content_bmpstring(i, len)
        }
        // all unknown values
        _ => Err(Err::Error(BerError::UnknownTag)),
    }
}

/// Parse the next bytes as the content of a BER object (combinator)
///
/// Content type is *not* checked, caller is reponsible of providing the correct tag
///
/// Caller is also responsible to check if parsing function consumed the expected number of
/// bytes (`header.len`).
///
/// The arguments of the parse function are: `(input, ber_object_header, max_recursion)`.
///
/// Example: manually parsing header and content
///
/// ```
/// # use der_parser::ber::*;
/// #
/// # let bytes = &[0x02, 0x03, 0x01, 0x00, 0x01];
/// let (i, header) = ber_read_element_header(bytes).expect("parsing failed");
/// let (rem, content) = parse_ber_content(header.tag)(i, &header, MAX_RECURSION)
///     .expect("parsing failed");
/// #
/// # assert_eq!(header.tag, BerTag::Integer);
/// ```
pub fn parse_ber_content<'a>(
    tag: BerTag,
) -> impl Fn(&'a [u8], &'_ BerObjectHeader, usize) -> BerResult<'a, BerObjectContent<'a>> {
    move |i: &[u8], hdr: &BerObjectHeader, max_recursion: usize| {
        ber_read_element_content_as(
            i,
            tag,
            hdr.len as usize,
            hdr.is_constructed(),
            max_recursion,
        )
    }
}

/// Parse a BER object, expecting a value with specified tag
pub fn parse_ber_with_tag(i: &[u8], tag: BerTag) -> BerResult {
    do_parse! {
        i,
        hdr: ber_read_element_header >>
             custom_check!(hdr.tag != tag, BerError::InvalidTag) >>
        o:   call!(ber_read_element_content_as, hdr.tag, hdr.len as usize, hdr.is_constructed(), MAX_RECURSION) >>
        ( BerObject::from_header_and_content(hdr, o) )
    }
}

/// Read end of content marker
#[inline]
pub fn parse_ber_endofcontent(i: &[u8]) -> BerResult {
    parse_ber_with_tag(i, BerTag::EndOfContent)
}

/// Read a boolean value
///
/// The encoding of a boolean value shall be primitive. The contents octets shall consist of a
/// single octet.
///
/// If the boolean value is FALSE, the octet shall be zero.
/// If the boolean value is TRUE, the octet shall be one byte, and have all bits set to one (0xff).
#[inline]
pub fn parse_ber_bool(i: &[u8]) -> BerResult {
    parse_ber_with_tag(i, BerTag::Boolean)
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
/// # #[macro_use] extern crate der_parser;
/// # extern crate nom;
/// # use der_parser::ber::parse_ber_integer;
/// # use der_parser::ber::{BerObject,BerObjectContent};
/// let empty = &b""[..];
/// let bytes = [0x02, 0x03, 0x01, 0x00, 0x01];
/// let expected  = BerObject::from_obj(BerObjectContent::Integer(b"\x01\x00\x01"));
/// assert_eq!(
///     parse_ber_integer(&bytes),
///     Ok((empty, expected))
/// );
/// ```
#[inline]
pub fn parse_ber_integer(i: &[u8]) -> BerResult {
    parse_ber_with_tag(i, BerTag::Integer)
}

/// Read an bitstring value
#[inline]
pub fn parse_ber_bitstring(i: &[u8]) -> BerResult {
    parse_ber_with_tag(i, BerTag::BitString)
}

/// Read an octetstring value
#[inline]
pub fn parse_ber_octetstring(i: &[u8]) -> BerResult {
    parse_ber_with_tag(i, BerTag::OctetString)
}

/// Read a null value
#[inline]
pub fn parse_ber_null(i: &[u8]) -> BerResult {
    parse_ber_with_tag(i, BerTag::Null)
}

/// Read an object identifier value
#[inline]
pub fn parse_ber_oid(i: &[u8]) -> BerResult {
    parse_ber_with_tag(i, BerTag::Oid)
}

/// Read an enumerated value
#[inline]
pub fn parse_ber_enum(i: &[u8]) -> BerResult {
    parse_ber_with_tag(i, BerTag::Enumerated)
}

/// Read a UTF-8 string value. The encoding is checked.
#[inline]
pub fn parse_ber_utf8string(i: &[u8]) -> BerResult {
    parse_ber_with_tag(i, BerTag::Utf8String)
}

/// Read a relative object identifier value
#[inline]
pub fn parse_ber_relative_oid(i: &[u8]) -> BerResult {
    parse_ber_with_tag(i, BerTag::RelativeOid)
}

/// Parse a sequence of BER elements
///
/// Read a sequence of BER objects, without any constraint on the types.
/// Sequence is parsed recursively, so if structured elements are found, they are parsed using the
/// same function.
///
/// To read a specific sequence of objects (giving the expected types), use the
/// [`parse_ber_sequence_defined`](macro.parse_ber_sequence_defined.html) macro.
#[inline]
pub fn parse_ber_sequence(i: &[u8]) -> BerResult {
    parse_ber_with_tag(i, BerTag::Sequence)
}

/// Parse a set of BER elements
///
/// Read a set of BER objects, without any constraint on the types.
/// Set is parsed recursively, so if structured elements are found, they are parsed using the
/// same function.
///
/// To read a specific set of objects (giving the expected types), use the
/// [`parse_ber_set_defined`](macro.parse_ber_set_defined.html) macro.
#[inline]
pub fn parse_ber_set(i: &[u8]) -> BerResult {
    parse_ber_with_tag(i, BerTag::Set)
}

/// Read a numeric string value. The content is verified to
/// contain only digits and spaces.
#[inline]
pub fn parse_ber_numericstring(i: &[u8]) -> BerResult {
    parse_ber_with_tag(i, BerTag::NumericString)
}

/// Read a printable string value. The content is verified to
/// contain only the allowed characters.
#[inline]
pub fn parse_ber_printablestring(i: &[u8]) -> BerResult {
    parse_ber_with_tag(i, BerTag::PrintableString)
}

/// Read a T61 string value
#[inline]
pub fn parse_ber_t61string(i: &[u8]) -> BerResult {
    parse_ber_with_tag(i, BerTag::T61String)
}

/// Read an IA5 string value. The content is verified to be ASCII.
#[inline]
pub fn parse_ber_ia5string(i: &[u8]) -> BerResult {
    parse_ber_with_tag(i, BerTag::Ia5String)
}

/// Read an UTC time value
#[inline]
pub fn parse_ber_utctime(i: &[u8]) -> BerResult {
    parse_ber_with_tag(i, BerTag::UtcTime)
}

/// Read a Generalized time value
#[inline]
pub fn parse_ber_generalizedtime(i: &[u8]) -> BerResult {
    parse_ber_with_tag(i, BerTag::GeneralizedTime)
}

/// Read a GeneralString value
#[inline]
pub fn parse_ber_generalstring(i: &[u8]) -> BerResult {
    parse_ber_with_tag(i, BerTag::GeneralString)
}

/// Read a BmpString value
#[inline]
pub fn parse_ber_bmpstring(i: &[u8]) -> BerResult {
    parse_ber_with_tag(i, BerTag::BmpString)
}

pub fn parse_ber_explicit_failed(i: &[u8], tag: BerTag) -> BerResult {
    Ok((
        i,
        BerObject::from_obj(BerObjectContent::ContextSpecific(tag, None)),
    ))
}

/// Parse an optional tagged object, applying function to get content
///
/// This function returns a `BerObject`, trying to read content as generic BER objects.
/// If parsing failed, return an optional object containing `None`.
///
/// This function will never fail: if parsing content failed, the BER value `Optional(None)` is
/// returned.
pub fn parse_ber_explicit_optional<F>(i: &[u8], tag: BerTag, f: F) -> BerResult
where
    F: Fn(&[u8]) -> BerResult,
{
    alt! {
        i,
        complete!(do_parse!(
            hdr:     ber_read_element_header >>
                     custom_check!(hdr.tag != tag, BerError::InvalidTag) >>
            content: f >>
            (
                BerObject::from_header_and_content(
                    hdr,
                    BerObjectContent::ContextSpecific(tag,Some(Box::new(content)))
                )
            )
        )) |
        complete!(call!(parse_ber_explicit_failed, tag))
    }
}

/// Parse an optional tagged object, applying function to get content
///
/// This function is deprecated, use
/// [parse_ber_explicit_optional](fn.parse_ber_explicit_optional.html) instead.
#[deprecated(
    since = "4.1.0",
    note = "Please use `parse_ber_explicit_optional` instead"
)]
#[inline]
pub fn parse_ber_explicit<F>(i: &[u8], tag: BerTag, f: F) -> BerResult
where
    F: Fn(&[u8]) -> BerResult,
{
    parse_ber_explicit_optional(i, tag, f)
}

/// call der *content* parsing function
pub fn parse_ber_implicit<F>(i: &[u8], tag: BerTag, f: F) -> BerResult
where
    F: Fn(&[u8], BerTag, usize) -> BerResult<BerObjectContent>,
{
    alt! {
        i,
        complete!(do_parse!(
            hdr:     ber_read_element_header >>
                     custom_check!(hdr.tag != tag, BerError::InvalidTag) >>
            content: call!(f, tag, hdr.len as usize) >>
            (
                BerObject::from_header_and_content(
                    hdr,
                    BerObjectContent::ContextSpecific(tag,Some(Box::new(BerObject::from_obj(content))))
                )
            )
        )) |
        complete!(call!(parse_ber_explicit_failed, tag))
    }
}

/// Parse BER object and try to decode it as a 32-bits unsigned integer
#[inline]
pub fn parse_ber_u32(i: &[u8]) -> BerResult<u32> {
    map_res(parse_ber_integer, |o| o.as_u32())(i)
}

/// Parse BER object and try to decode it as a 64-bits unsigned integer
#[inline]
pub fn parse_ber_u64(i: &[u8]) -> BerResult<u64> {
    map_res(parse_ber_integer, |o| o.as_u64())(i)
}

/// Parse BER object recursively, specifying the maximum recursion depth
///
/// Return a tuple containing the remaining (unparsed) bytes and the BER Object, or an error.
///
/// ### Example
///
/// ```
/// use der_parser::ber::{parse_ber_recursive, BerTag};
///
/// let bytes = &[0x02, 0x03, 0x01, 0x00, 0x01];
/// let (_, obj) = parse_ber_recursive(bytes, 1).expect("parsing failed");
///
/// assert_eq!(obj.header.tag, BerTag::Integer);
/// ```
pub fn parse_ber_recursive(i: &[u8], max_depth: usize) -> BerResult {
    custom_check!(i, max_depth == 0, BerError::BerMaxDepth)?;
    let (rem, hdr) = ber_read_element_header(i)?;
    custom_check!(
        i,
        hdr.len as usize > i.len() || hdr.len > u64::from(::std::u32::MAX),
        BerError::InvalidLength
    )?;
    match hdr.class {
        BerClass::Universal | BerClass::Private => (),
        _ => {
            return map!(rem, take!(hdr.len), |b| {
                BerObject::from_header_and_content(hdr, BerObjectContent::Unknown(hdr.tag, b))
            })
        }
    }
    match ber_read_element_content_as(
        rem,
        hdr.tag,
        hdr.len as usize,
        hdr.is_constructed(),
        max_depth,
    ) {
        Ok((rem, content)) => Ok((rem, BerObject::from_header_and_content(hdr, content))),
        Err(Err::Error(BerError::UnknownTag)) => map!(rem, take!(hdr.len), |b| {
            BerObject::from_header_and_content(hdr, BerObjectContent::Unknown(hdr.tag, b))
        }),
        Err(e) => Err(e),
    }
}

/// Parse BER object recursively
///
/// Return a tuple containing the remaining (unparsed) bytes and the BER Object, or an error.
///
/// *Note: this is the same as calling `parse_ber_recursive` with `MAX_RECURSION`.
///
/// ### Example
///
/// ```
/// use der_parser::ber::{parse_ber, BerTag};
///
/// let bytes = &[0x02, 0x03, 0x01, 0x00, 0x01];
/// let (_, obj) = parse_ber(bytes).expect("parsing failed");
///
/// assert_eq!(obj.header.tag, BerTag::Integer);
/// ```
#[inline]
pub fn parse_ber(i: &[u8]) -> BerResult {
    parse_ber_recursive(i, MAX_RECURSION)
}

#[test]
fn test_numericstring() {
    assert_eq!(
        ber_read_content_numericstring(b" 0123  4495768 ", 15),
        Ok((
            [].as_ref(),
            BerObjectContent::NumericString(" 0123  4495768 ")
        )),
    );
    assert_eq!(
        ber_read_content_numericstring(b"", 0),
        Ok(([].as_ref(), BerObjectContent::NumericString(""))),
    );
    assert!(ber_read_content_numericstring(b"123a", 4).is_err());
}

#[test]
fn test_printablestring() {
    assert_eq!(
        ber_read_content_printablestring(b"AZaz09 '()+,-./:=?", 18),
        Ok((
            [].as_ref(),
            BerObjectContent::PrintableString("AZaz09 '()+,-./:=?")
        )),
    );
    assert_eq!(
        ber_read_content_printablestring(b"", 0),
        Ok(([].as_ref(), BerObjectContent::PrintableString(""))),
    );
    assert!(ber_read_content_printablestring(b"]", 1).is_err());
}

#[test]
fn test_ia5string() {
    assert_eq!(
        ber_read_content_ia5string(b"AZaz09 '()+,-./:=?[]{}\0\n", 24),
        Ok((
            [].as_ref(),
            BerObjectContent::IA5String("AZaz09 '()+,-./:=?[]{}\0\n")
        )),
    );
    assert_eq!(
        ber_read_content_ia5string(b"", 0),
        Ok(([].as_ref(), BerObjectContent::IA5String(""))),
    );
    assert!(ber_read_content_ia5string(b"\xFF", 1).is_err());
}

#[test]
fn test_utf8string() {
    assert_eq!(
        ber_read_content_utf8string("AZaz09 '()+,-./:=?[]{}\0\nüÜ".as_ref(), 28),
        Ok((
            [].as_ref(),
            BerObjectContent::UTF8String("AZaz09 '()+,-./:=?[]{}\0\nüÜ")
        )),
    );
    assert_eq!(
        ber_read_content_utf8string(b"", 0),
        Ok(([].as_ref(), BerObjectContent::UTF8String(""))),
    );
    assert!(ber_read_content_utf8string(b"\xe2\x28\xa1", 3).is_err());
}
