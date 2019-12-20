use crate::ber::*;
use crate::error::*;
use crate::oid::*;
use nom::bytes::streaming::take;
use nom::combinator::{map, map_res};
use nom::error::ErrorKind;
use nom::number::streaming::be_u8;
use nom::{Err, Needed};

/// Maximum recursion limit
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

pub(crate) fn parse_identifier(i: &[u8]) -> BerResult<(u8, u8, u32)> {
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

        Ok((&i[tag_byte_count..], (a, b, c)))
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

fn ber_read_relative_oid(i: &[u8]) -> Result<Vec<u64>, u64> {
    let mut oid = Vec::new();
    let mut acc: u64;

    if i.is_empty() {
        return Ok(oid);
    };

    acc = 0;
    for &c in &i[0..] {
        acc = (acc << 7) | u64::from(c & 0b0111_1111);
        if (c & (1 << 7)) == 0 {
            oid.push(acc);
            acc = 0;
        }
    }

    match acc {
        0 => Ok(oid),
        _ => Err(acc),
    }
}

fn ber_read_oid(i: &[u8]) -> Result<Vec<u64>, u64> {
    let mut oid = Vec::new();
    let mut index = 0;

    if i.is_empty() {
        return Err(0);
    };

    /* first element = X*40 + Y (See 8.19.4) */
    let acc = u64::from(i[0]);
    if acc < 128 {
        oid.push(acc / 40);
        oid.push(acc % 40);
        index = 1;
    }

    let rel_oid = ber_read_relative_oid(&i[index..])?;
    oid.extend(&rel_oid);
    Ok(oid)
}

/// Read an object header
pub fn ber_read_element_header(i: &[u8]) -> BerResult<BerObjectHeader> {
    do_parse! {
        i,
        el:   parse_identifier >>
        len:  parse_ber_length_byte >>
        llen: cond!(len.0 == 1, take!(len.1)) >>
        ( {
            let len : u64 = match len.0 {
                0 => u64::from(len.1),
                _ => {
                    // if len is 0xff -> error (8.1.3.5)
                    if len.1 == 0b0111_1111 {
                        return Err(::nom::Err::Error(BerError::InvalidTag));
                    }
                    // XXX llen: test if 0 (indefinite form), if len is 0xff -> error
                    match bytes_to_u64(llen.unwrap()) {
                        Ok(l)  => l,
                        Err(_) => { return Err(::nom::Err::Error(BerError::InvalidTag)); },
                    }
                },
            };
            BerObjectHeader {
                class: el.0,
                structured: el.1,
                tag: BerTag(el.2),
                len,
            }
        } )
    }
}

#[inline]
pub(crate) fn ber_read_content_eoc(i: &[u8]) -> BerResult<BerObjectContent> {
    Ok((i, BerObjectContent::EndOfContent))
}

#[inline]
pub(crate) fn ber_read_content_bool(i: &[u8]) -> BerResult<BerObjectContent> {
    match be_u8(i) {
        Ok((rem, 0)) => Ok((rem, BerObjectContent::Boolean(false))),
        Ok((rem, _)) => Ok((rem, BerObjectContent::Boolean(true))),
        Err(e) => Err(e),
    }
}

#[inline]
pub(crate) fn ber_read_content_integer(i: &[u8], len: usize) -> BerResult<BerObjectContent> {
    map(take(len), BerObjectContent::Integer)(i)
}

// XXX check if constructed (8.6.3)
#[inline]
pub(crate) fn ber_read_content_bitstring(i: &[u8], len: usize) -> BerResult<BerObjectContent> {
    do_parse! {
        i,
        ignored_bits: be_u8 >>
                      custom_check!(len == 0, BerError::InvalidLength) >>
        s:            take!(len - 1) >>
        ( BerObjectContent::BitString(ignored_bits,BitStringObject{ data:s }) )
    }
}

// XXX check if constructed (8.7)
#[inline]
pub(crate) fn ber_read_content_octetstring(i: &[u8], len: usize) -> BerResult<BerObjectContent> {
    map(take(len), BerObjectContent::OctetString)(i)
}

#[inline]
pub(crate) fn ber_read_content_null(i: &[u8]) -> BerResult<BerObjectContent> {
    Ok((i, BerObjectContent::Null))
}

// XXX check if primitive (8.19.1)
#[inline]
pub(crate) fn ber_read_content_oid(i: &[u8], len: usize) -> BerResult<BerObjectContent> {
    do_parse! {
        i,
             error_if!(len == 0, ErrorKind::LengthValue) >>
        oid: map_res!(take!(len),ber_read_oid) >>
        ( BerObjectContent::OID(Oid::from(&oid)) )
    }
}

// XXX check if primitive (8.4)
#[inline]
pub(crate) fn ber_read_content_enum(i: &[u8], len: usize) -> BerResult<BerObjectContent> {
    parse_hex_to_u64!(i, len).map(|(rem, i)| (rem, BerObjectContent::Enum(i)))
}

// XXX check if constructed, or indefinite length (8.21)
#[inline]
pub(crate) fn ber_read_content_utf8string(i: &[u8], len: usize) -> BerResult<BerObjectContent> {
    map!(i, take!(len), |s| BerObjectContent::UTF8String(s))
}

#[inline]
pub(crate) fn ber_read_content_relativeoid(i: &[u8], len: usize) -> BerResult<BerObjectContent> {
    do_parse! {
        i,
             custom_check!(len == 0, BerError::InvalidLength) >>
        oid: map_res!(take!(len), ber_read_relative_oid) >>
        ( BerObjectContent::RelativeOID(Oid::from(&oid)) )
    }
}

#[inline]
pub(crate) fn ber_read_content_sequence(
    i: &[u8],
    len: usize,
    depth: usize,
) -> BerResult<BerObjectContent> {
    if len == 0 {
        // indefinite form
        // read until end-of-content
        map!(
            i,
            many_till!(
                call!(parse_ber_recursive, depth + 1),
                parse_ber_endofcontent
            ),
            |(l, _)| { BerObjectContent::Sequence(l) }
        )
    } else {
        map!(
            i,
            flat_take!(
                len,
                many0!(complete!(call!(parse_ber_recursive, depth + 1)))
            ),
            |l| { BerObjectContent::Sequence(l) }
        )
    }
}

#[inline]
pub(crate) fn ber_read_content_set(
    i: &[u8],
    len: usize,
    depth: usize,
) -> BerResult<BerObjectContent> {
    if len == 0 {
        // indefinite form
        // read until end-of-content
        map!(
            i,
            many_till!(
                call!(parse_ber_recursive, depth + 1),
                parse_ber_endofcontent
            ),
            |(l, _)| { BerObjectContent::Set(l) }
        )
    } else {
        map!(
            i,
            flat_take!(
                len,
                many0!(complete!(call!(parse_ber_recursive, depth + 1)))
            ),
            |l| { BerObjectContent::Set(l) }
        )
    }
}

// XXX check if constructed, or indefinite length (8.21)
#[inline]
pub(crate) fn ber_read_content_numericstring(i: &[u8], len: usize) -> BerResult<BerObjectContent> {
    map!(i, take!(len), |s| BerObjectContent::NumericString(s))
}

// XXX check if constructed, or indefinite length (8.21)
#[inline]
pub(crate) fn ber_read_content_printablestring(
    i: &[u8],
    len: usize,
) -> BerResult<BerObjectContent> {
    map!(i, take!(len), |s| BerObjectContent::PrintableString(s))
}

// XXX check if constructed, or indefinite length (8.21)
#[inline]
pub(crate) fn ber_read_content_t61string(i: &[u8], len: usize) -> BerResult<BerObjectContent> {
    map(take(len), BerObjectContent::T61String)(i)
}

// XXX check if constructed, or indefinite length (8.21)
#[inline]
pub(crate) fn ber_read_content_ia5string(i: &[u8], len: usize) -> BerResult<BerObjectContent> {
    map!(i, take!(len), |s| BerObjectContent::IA5String(s))
}

#[inline]
pub(crate) fn ber_read_content_utctime(i: &[u8], len: usize) -> BerResult<BerObjectContent> {
    map(take(len), BerObjectContent::UTCTime)(i)
}

#[inline]
pub(crate) fn ber_read_content_generalizedtime(
    i: &[u8],
    len: usize,
) -> BerResult<BerObjectContent> {
    map(take(len), BerObjectContent::GeneralizedTime)(i)
}

// XXX check if constructed, or indefinite length (8.21)
#[inline]
pub(crate) fn ber_read_content_generalstring(i: &[u8], len: usize) -> BerResult<BerObjectContent> {
    map(take(len), BerObjectContent::GeneralString)(i)
}

// XXX check if constructed, or indefinite length (8.21)
#[inline]
pub(crate) fn ber_read_content_bmpstring(i: &[u8], len: usize) -> BerResult<BerObjectContent> {
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
    depth: usize,
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
            custom_check!(i, constructed, BerError::Unsupported)?; // XXX valid in BER
            ber_read_content_bitstring(i, len)
        }
        // 0x04: octetstring
        BerTag::OctetString => {
            custom_check!(i, constructed, BerError::Unsupported)?; // XXX valid in BER
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
            custom_check!(i, constructed, BerError::ConstructUnexpected)?;
            ber_read_content_oid(i, len)
        }
        // 0x0a: enumerated
        BerTag::Enumerated => {
            custom_check!(i, constructed, BerError::ConstructUnexpected)?;
            ber_read_content_enum(i, len)
        }
        // 0x0c: UTF8String
        BerTag::Utf8String => {
            custom_check!(i, constructed, BerError::Unsupported)?; // XXX valid in BER
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
            ber_read_content_sequence(i, len, depth)
        }
        // 0x11: set
        BerTag::Set => {
            custom_check!(i, !constructed, BerError::ConstructExpected)?;
            ber_read_content_set(i, len, depth)
        }
        // 0x12: numericstring
        BerTag::NumericString => {
            custom_check!(i, constructed, BerError::Unsupported)?; // XXX valid in BER
            ber_read_content_numericstring(i, len)
        }
        // 0x13: printablestring
        BerTag::PrintableString => {
            custom_check!(i, constructed, BerError::Unsupported)?; // XXX valid in BER
            ber_read_content_printablestring(i, len)
        }
        // 0x14: t61string
        BerTag::T61String => {
            custom_check!(i, constructed, BerError::Unsupported)?; // XXX valid in BER
            ber_read_content_t61string(i, len)
        }
        // 0x16: ia5string
        BerTag::Ia5String => {
            custom_check!(i, constructed, BerError::Unsupported)?; // XXX valid in BER
            ber_read_content_ia5string(i, len)
        }
        // 0x17: utctime
        BerTag::UtcTime => ber_read_content_utctime(i, len),
        // 0x18: generalizedtime
        BerTag::GeneralizedTime => ber_read_content_generalizedtime(i, len),
        // 0x1b: generalstring
        BerTag::GeneralString => {
            custom_check!(i, constructed, BerError::Unsupported)?; // XXX valid in BER
            ber_read_content_generalstring(i, len)
        }
        // 0x1e: bmpstring
        BerTag::BmpString => {
            custom_check!(i, constructed, BerError::Unsupported)?; // XXX valid in BER
            ber_read_content_bmpstring(i, len)
        }
        // all unknown values
        _ => Err(Err::Error(BerError::UnknownTag)),
    }
}
//
/// Parse a BER object, expecting a value with specificed tag
pub fn parse_ber_with_tag(i: &[u8], tag: BerTag) -> BerResult {
    do_parse! {
        i,
        hdr: ber_read_element_header >>
             custom_check!(hdr.tag != tag, BerError::InvalidTag) >>
        o:   call!(ber_read_element_content_as, hdr.tag, hdr.len as usize, hdr.is_constructed(), 0) >>
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

/// Read a UTF-8 string value
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

/// Read a numeric string value
#[inline]
pub fn parse_ber_numericstring(i: &[u8]) -> BerResult {
    parse_ber_with_tag(i, BerTag::NumericString)
}

/// Read a printable string value
#[inline]
pub fn parse_ber_printablestring(i: &[u8]) -> BerResult {
    parse_ber_with_tag(i, BerTag::PrintableString)
}

/// Read a T61 string value
#[inline]
pub fn parse_ber_t61string(i: &[u8]) -> BerResult {
    parse_ber_with_tag(i, BerTag::T61String)
}

/// Read an IA5 string value
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

pub fn parse_ber_explicit<F>(i: &[u8], tag: BerTag, f: F) -> BerResult
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

fn parse_ber_recursive(i: &[u8], depth: usize) -> BerResult {
    custom_check!(i, depth > MAX_RECURSION, BerError::BerMaxDepth)?;
    let (rem, hdr) = ber_read_element_header(i)?;
    custom_check!(
        i,
        hdr.len as usize > i.len() || hdr.len > u64::from(::std::u32::MAX),
        BerError::InvalidLength
    )?;
    match hdr.class {
        // universal
        0b00 |
        // private
        0b11 => (),
        // application
        0b01 |
        // context-specific
        0b10 => return map!(
            rem,
            take!(hdr.len),
            |b| { BerObject::from_header_and_content(hdr,BerObjectContent::Unknown(hdr.tag, b)) }
        ),
        _    => { return Err(Err::Error(BerError::InvalidClass)); },
    }
    match ber_read_element_content_as(rem, hdr.tag, hdr.len as usize, hdr.is_constructed(), depth) {
        Ok((rem, content)) => Ok((rem, BerObject::from_header_and_content(hdr, content))),
        Err(Err::Error(BerError::UnknownTag)) => map!(rem, take!(hdr.len), |b| {
            BerObject::from_header_and_content(hdr, BerObjectContent::Unknown(hdr.tag, b))
        }),
        Err(e) => Err(e),
    }
}

/// Parse BER object
#[inline]
pub fn parse_ber(i: &[u8]) -> BerResult {
    parse_ber_recursive(i, 0)
}
