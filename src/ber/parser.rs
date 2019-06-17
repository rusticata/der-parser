use crate::ber::*;
use crate::error::*;
use crate::oid::*;
use nom::{be_u8, Context, Err, ErrorKind, IResult, Needed};

/// Maximum recursion limit
pub const MAX_RECURSION: usize = 50;

/// Try to parse input bytes as u64
pub(crate) fn bytes_to_u64(s: &[u8]) -> Result<u64, BerError> {
    let mut u: u64 = 0;
    for &c in s {
        u = u.checked_shl(8).ok_or(BerError::IntegerTooLarge)?;
        u |= c as u64;
    }
    Ok(u)
}

pub(crate) fn parse_identifier(i: &[u8]) -> IResult<&[u8], (u8, u8, u8)> {
    if i.is_empty() {
        Err(Err::Incomplete(Needed::Size(1)))
    } else {
        let a = i[0] >> 6;
        let b = if i[0] & 0b0010_0000 != 0 { 1 } else { 0 };
        let c = i[0] & 0b0001_1111;
        Ok((&i[1..], (a, b, c)))
    }
}

pub(crate) fn parse_ber_length_byte(i: &[u8]) -> IResult<&[u8], (u8, u8)> {
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
        acc = (acc << 7) | (c & 0b0111_1111) as u64;
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
    let acc = i[0] as u64;
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
pub fn ber_read_element_header(i: &[u8]) -> IResult<&[u8], BerObjectHeader> {
    do_parse! {
        i,
        el:   parse_identifier >>
        len:  parse_ber_length_byte >>
        llen: cond!(len.0 == 1, take!(len.1)) >>
        ( {
            let len : u64 = match len.0 {
                0 => len.1 as u64,
                _ => {
                    // if len is 0xff -> error (8.1.3.5)
                    if len.1 == 0b0111_1111 {
                        return Err(::nom::Err::Error(error_position!(&i[1..], ErrorKind::Custom(BER_INVALID_LENGTH))));
                    }
                    // XXX llen: test if 0 (indefinite form), if len is 0xff -> error
                    match bytes_to_u64(llen.unwrap()) {
                        Ok(l)  => l,
                        Err(_) => { return Err(::nom::Err::Error(error_position!(llen.unwrap(), ErrorKind::Custom(BER_TAG_ERROR)))); },
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
pub(crate) fn ber_read_content_eoc(i: &[u8]) -> IResult<&[u8], BerObjectContent> {
    Ok((i, BerObjectContent::EndOfContent))
}

#[inline]
pub(crate) fn ber_read_content_bool(i: &[u8]) -> IResult<&[u8], BerObjectContent> {
    match be_u8(i) {
        Ok((rem, 0)) => Ok((rem, BerObjectContent::Boolean(false))),
        Ok((rem, _)) => Ok((rem, BerObjectContent::Boolean(true))),
        Err(e) => Err(e),
    }
}

#[inline]
pub(crate) fn ber_read_content_integer(i: &[u8], len: usize) -> IResult<&[u8], BerObjectContent> {
    map!(i, take!(len), |i| { BerObjectContent::Integer(i) })
}

// XXX check if constructed (8.6.3)
#[inline]
pub(crate) fn ber_read_content_bitstring(i: &[u8], len: usize) -> IResult<&[u8], BerObjectContent> {
    do_parse! {
        i,
        ignored_bits: be_u8 >>
                      error_if!(len == 0, ErrorKind::Custom(BER_INVALID_LENGTH)) >>
        s:            take!(len - 1) >>
        ( BerObjectContent::BitString(ignored_bits,BitStringObject{ data:s }) )
    }
}

// XXX check if constructed (8.7)
#[inline]
pub(crate) fn ber_read_content_octetstring(
    i: &[u8],
    len: usize,
) -> IResult<&[u8], BerObjectContent> {
    map!(i, take!(len), |s| BerObjectContent::OctetString(s))
}

#[inline]
pub(crate) fn ber_read_content_null(i: &[u8]) -> IResult<&[u8], BerObjectContent> {
    Ok((i, BerObjectContent::Null))
}

// XXX check if primitive (8.19.1)
#[inline]
pub(crate) fn ber_read_content_oid(i: &[u8], len: usize) -> IResult<&[u8], BerObjectContent> {
    do_parse! {
        i,
             error_if!(len == 0, ErrorKind::LengthValue) >>
        oid: map_res!(take!(len),ber_read_oid) >>
        ( BerObjectContent::OID(Oid::from(&oid)) )
    }
}

// XXX check if primitive (8.4)
#[inline]
pub(crate) fn ber_read_content_enum(i: &[u8], len: usize) -> IResult<&[u8], BerObjectContent> {
    parse_hex_to_u64!(i, len).map(|(rem, i)| (rem, BerObjectContent::Enum(i)))
}

// XXX check if constructed, or indefinite length (8.21)
#[inline]
pub(crate) fn ber_read_content_utf8string(
    i: &[u8],
    len: usize,
) -> IResult<&[u8], BerObjectContent> {
    map!(i, take!(len), |s| BerObjectContent::UTF8String(s))
}

#[inline]
pub(crate) fn ber_read_content_relativeoid(
    i: &[u8],
    len: usize,
) -> IResult<&[u8], BerObjectContent> {
    do_parse! {
        i,
             error_if!(len == 0, ErrorKind::LengthValue) >>
        oid: map_res!(take!(len), ber_read_relative_oid) >>
        ( BerObjectContent::RelativeOID(Oid::from(&oid)) )
    }
}

#[inline]
pub(crate) fn ber_read_content_sequence(
    i: &[u8],
    len: usize,
    depth: usize,
) -> IResult<&[u8], BerObjectContent> {
    if len == 0 {
        // indefinite form
        // read until end-of-content
        map!(
            i,
            many_till!(
                apply!(parse_ber_recursive, depth + 1),
                parse_ber_endofcontent
            ),
            |(l, _)| { BerObjectContent::Sequence(l) }
        )
    } else {
        map!(
            i,
            flat_take!(
                len,
                many0!(complete!(apply!(parse_ber_recursive, depth + 1)))
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
) -> IResult<&[u8], BerObjectContent> {
    if len == 0 {
        // indefinite form
        // read until end-of-content
        map!(
            i,
            many_till!(
                apply!(parse_ber_recursive, depth + 1),
                parse_ber_endofcontent
            ),
            |(l, _)| { BerObjectContent::Set(l) }
        )
    } else {
        map!(
            i,
            flat_take!(
                len,
                many0!(complete!(apply!(parse_ber_recursive, depth + 1)))
            ),
            |l| { BerObjectContent::Set(l) }
        )
    }
}

// XXX check if constructed, or indefinite length (8.21)
#[inline]
pub(crate) fn ber_read_content_numericstring(
    i: &[u8],
    len: usize,
) -> IResult<&[u8], BerObjectContent> {
    map!(i, take!(len), |s| BerObjectContent::NumericString(s))
}

// XXX check if constructed, or indefinite length (8.21)
#[inline]
pub(crate) fn ber_read_content_printablestring(
    i: &[u8],
    len: usize,
) -> IResult<&[u8], BerObjectContent> {
    map!(i, take!(len), |s| BerObjectContent::PrintableString(s))
}

// XXX check if constructed, or indefinite length (8.21)
#[inline]
pub(crate) fn ber_read_content_t61string(i: &[u8], len: usize) -> IResult<&[u8], BerObjectContent> {
    map!(i, take!(len), |s| BerObjectContent::T61String(s))
}

// XXX check if constructed, or indefinite length (8.21)
#[inline]
pub(crate) fn ber_read_content_ia5string(i: &[u8], len: usize) -> IResult<&[u8], BerObjectContent> {
    map!(i, take!(len), |s| BerObjectContent::IA5String(s))
}

#[inline]
pub(crate) fn ber_read_content_utctime(i: &[u8], len: usize) -> IResult<&[u8], BerObjectContent> {
    map!(i, take!(len), |s| BerObjectContent::UTCTime(s))
}

#[inline]
pub(crate) fn ber_read_content_generalizedtime(
    i: &[u8],
    len: usize,
) -> IResult<&[u8], BerObjectContent> {
    map!(i, take!(len), |s| BerObjectContent::GeneralizedTime(s))
}

// XXX check if constructed, or indefinite length (8.21)
#[inline]
pub(crate) fn ber_read_content_generalstring(
    i: &[u8],
    len: usize,
) -> IResult<&[u8], BerObjectContent> {
    map!(i, take!(len), |s| BerObjectContent::GeneralString(s))
}

// XXX check if constructed, or indefinite length (8.21)
#[inline]
pub(crate) fn ber_read_content_bmpstring(i: &[u8], len: usize) -> IResult<&[u8], BerObjectContent> {
    map!(i, take!(len), |s| BerObjectContent::BmpString(s))
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
) -> IResult<&[u8], BerObjectContent> {
    if i.len() < len {
        return Err(Err::Incomplete(Needed::Size(len)));
    }
    match tag {
        // 0x00 end-of-content
        BerTag::EndOfContent => {
            error_if!(i, len != 0, ErrorKind::Custom(BER_INVALID_LENGTH))?;
            ber_read_content_eoc(i)
        }
        // 0x01 bool
        BerTag::Boolean => {
            error_if!(i, len != 1, ErrorKind::Custom(BER_INVALID_LENGTH))?;
            ber_read_content_bool(i)
        }
        // 0x02
        BerTag::Integer => {
            error_if!(i, constructed, ErrorKind::Custom(BER_STRUCT_ERROR))?;
            ber_read_content_integer(i, len)
        }
        // 0x03: bitstring
        BerTag::BitString => {
            error_if!(i, constructed, ErrorKind::Custom(BER_UNSUPPORTED))?; // XXX valid in BER
            ber_read_content_bitstring(i, len)
        }
        // 0x04: octetstring
        BerTag::OctetString => {
            error_if!(i, constructed, ErrorKind::Custom(BER_UNSUPPORTED))?; // XXX valid in BER
            ber_read_content_octetstring(i, len)
        }
        // 0x05: null
        BerTag::Null => {
            error_if!(i, constructed, ErrorKind::Custom(BER_STRUCT_ERROR))?;
            error_if!(i, len != 0, ErrorKind::Custom(BER_INVALID_LENGTH))?;
            ber_read_content_null(i)
        }
        // 0x06: object identified
        BerTag::Oid => {
            error_if!(i, constructed, ErrorKind::Custom(BER_STRUCT_ERROR))?;
            ber_read_content_oid(i, len)
        }
        // 0x0a: enumerated
        BerTag::Enumerated => {
            error_if!(i, constructed, ErrorKind::Custom(BER_STRUCT_ERROR))?;
            ber_read_content_enum(i, len)
        }
        // 0x0c: UTF8String
        BerTag::Utf8String => {
            error_if!(i, constructed, ErrorKind::Custom(BER_UNSUPPORTED))?; // XXX valid in BER
            ber_read_content_utf8string(i, len)
        }
        // 0x0d: relative object identified
        BerTag::RelativeOid => {
            error_if!(i, constructed, ErrorKind::Custom(BER_STRUCT_ERROR))?;
            ber_read_content_relativeoid(i, len)
        }
        // 0x10: sequence
        BerTag::Sequence => {
            error_if!(i, !constructed, ErrorKind::Custom(BER_STRUCT_ERROR))?;
            ber_read_content_sequence(i, len, depth)
        }
        // 0x11: set
        BerTag::Set => {
            error_if!(i, !constructed, ErrorKind::Custom(BER_STRUCT_ERROR))?;
            ber_read_content_set(i, len, depth)
        }
        // 0x12: numericstring
        BerTag::NumericString => {
            error_if!(i, constructed, ErrorKind::Custom(BER_UNSUPPORTED))?; // XXX valid in BER
            ber_read_content_numericstring(i, len)
        }
        // 0x13: printablestring
        BerTag::PrintableString => {
            error_if!(i, constructed, ErrorKind::Custom(BER_UNSUPPORTED))?; // XXX valid in BER
            ber_read_content_printablestring(i, len)
        }
        // 0x14: t61string
        BerTag::T61String => {
            error_if!(i, constructed, ErrorKind::Custom(BER_UNSUPPORTED))?; // XXX valid in BER
            ber_read_content_t61string(i, len)
        }
        // 0x16: ia5string
        BerTag::Ia5String => {
            error_if!(i, constructed, ErrorKind::Custom(BER_UNSUPPORTED))?; // XXX valid in BER
            ber_read_content_ia5string(i, len)
        }
        // 0x17: utctime
        BerTag::UtcTime => ber_read_content_utctime(i, len),
        // 0x18: generalizedtime
        BerTag::GeneralizedTime => ber_read_content_generalizedtime(i, len),
        // 0x1b: generalstring
        BerTag::GeneralString => {
            error_if!(i, constructed, ErrorKind::Custom(BER_UNSUPPORTED))?; // XXX valid in BER
            ber_read_content_generalstring(i, len)
        }
        // 0x1e: bmpstring
        BerTag::BmpString => {
            error_if!(i, constructed, ErrorKind::Custom(BER_UNSUPPORTED))?; // XXX valid in BER
            ber_read_content_bmpstring(i, len)
        }
        // all unknown values
        _ => Err(Err::Error(error_position!(
            i,
            ErrorKind::Custom(BER_TAG_UNKNOWN)
        ))),
    }
}

/// Parse a BER object, expecting a value with specificed tag
pub fn parse_ber_with_tag(i: &[u8], tag: BerTag) -> IResult<&[u8], BerObject> {
    do_parse! {
        i,
        hdr: ber_read_element_header >>
             error_if!(hdr.tag != tag, ErrorKind::Custom(BER_TAG_ERROR)) >>
        o:   apply!(ber_read_element_content_as, hdr.tag, hdr.len as usize, hdr.is_constructed(), 0) >>
        ( BerObject::from_header_and_content(hdr, o) )
    }
}

/// Read end of content marker
#[inline]
pub fn parse_ber_endofcontent(i: &[u8]) -> IResult<&[u8], BerObject> {
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
pub fn parse_ber_bool(i: &[u8]) -> IResult<&[u8], BerObject> {
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
/// # use nom::IResult;
/// # use der_parser::ber::parse_ber_integer;
/// # use der_parser::ber::{BerObject,BerObjectContent};
/// # fn main() {
/// let empty = &b""[..];
/// let bytes = [0x02, 0x03, 0x01, 0x00, 0x01];
/// let expected  = BerObject::from_obj(BerObjectContent::Integer(b"\x01\x00\x01"));
/// assert_eq!(
///     parse_ber_integer(&bytes),
///     Ok((empty, expected))
/// );
/// # }
/// ```
#[inline]
pub fn parse_ber_integer(i: &[u8]) -> IResult<&[u8], BerObject> {
    parse_ber_with_tag(i, BerTag::Integer)
}

/// Read an bitstring value
#[inline]
pub fn parse_ber_bitstring(i: &[u8]) -> IResult<&[u8], BerObject> {
    parse_ber_with_tag(i, BerTag::BitString)
}

/// Read an octetstring value
#[inline]
pub fn parse_ber_octetstring(i: &[u8]) -> IResult<&[u8], BerObject> {
    parse_ber_with_tag(i, BerTag::OctetString)
}

/// Read a null value
#[inline]
pub fn parse_ber_null(i: &[u8]) -> IResult<&[u8], BerObject> {
    parse_ber_with_tag(i, BerTag::Null)
}

/// Read an object identifier value
#[inline]
pub fn parse_ber_oid(i: &[u8]) -> IResult<&[u8], BerObject> {
    parse_ber_with_tag(i, BerTag::Oid)
}

/// Read an enumerated value
#[inline]
pub fn parse_ber_enum(i: &[u8]) -> IResult<&[u8], BerObject> {
    parse_ber_with_tag(i, BerTag::Enumerated)
}

/// Read a UTF-8 string value
#[inline]
pub fn parse_ber_utf8string(i: &[u8]) -> IResult<&[u8], BerObject> {
    parse_ber_with_tag(i, BerTag::Utf8String)
}

/// Read a relative object identifier value
#[inline]
pub fn parse_ber_relative_oid(i: &[u8]) -> IResult<&[u8], BerObject> {
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
pub fn parse_ber_sequence(i: &[u8]) -> IResult<&[u8], BerObject> {
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
pub fn parse_ber_set(i: &[u8]) -> IResult<&[u8], BerObject> {
    parse_ber_with_tag(i, BerTag::Set)
}

/// Read a numeric string value
#[inline]
pub fn parse_ber_numericstring(i: &[u8]) -> IResult<&[u8], BerObject> {
    parse_ber_with_tag(i, BerTag::NumericString)
}

/// Read a printable string value
#[inline]
pub fn parse_ber_printablestring(i: &[u8]) -> IResult<&[u8], BerObject> {
    parse_ber_with_tag(i, BerTag::PrintableString)
}

/// Read a T61 string value
#[inline]
pub fn parse_ber_t61string(i: &[u8]) -> IResult<&[u8], BerObject> {
    parse_ber_with_tag(i, BerTag::T61String)
}

/// Read an IA5 string value
#[inline]
pub fn parse_ber_ia5string(i: &[u8]) -> IResult<&[u8], BerObject> {
    parse_ber_with_tag(i, BerTag::Ia5String)
}

/// Read an UTC time value
#[inline]
pub fn parse_ber_utctime(i: &[u8]) -> IResult<&[u8], BerObject> {
    parse_ber_with_tag(i, BerTag::UtcTime)
}

/// Read a Generalized time value
#[inline]
pub fn parse_ber_generalizedtime(i: &[u8]) -> IResult<&[u8], BerObject> {
    parse_ber_with_tag(i, BerTag::GeneralizedTime)
}

/// Read a GeneralString value
#[inline]
pub fn parse_ber_generalstring(i: &[u8]) -> IResult<&[u8], BerObject> {
    parse_ber_with_tag(i, BerTag::GeneralString)
}

/// Read a BmpString value
#[inline]
pub fn parse_ber_bmpstring(i: &[u8]) -> IResult<&[u8], BerObject> {
    parse_ber_with_tag(i, BerTag::BmpString)
}

pub fn parse_ber_explicit_failed(i: &[u8], tag: BerTag) -> IResult<&[u8], BerObject, u32> {
    value!(
        i,
        BerObject::from_obj(BerObjectContent::ContextSpecific(tag, None))
    )
}

pub fn parse_ber_explicit<F>(i: &[u8], tag: BerTag, f: F) -> IResult<&[u8], BerObject, u32>
where
    F: Fn(&[u8]) -> IResult<&[u8], BerObject, u32>,
{
    alt_complete! {
        i,
        do_parse!(
            hdr:     ber_read_element_header >>
            error_if!(hdr.tag != tag, ErrorKind::Custom(BER_TAG_ERROR)) >>
            content: f >>
            (
                BerObject::from_header_and_content(
                    hdr,
                    BerObjectContent::ContextSpecific(tag,Some(Box::new(content)))
                )
            )
        ) |
        apply!(parse_ber_explicit_failed, tag)
    }
}

/// call der *content* parsing function
pub fn parse_ber_implicit<F>(i: &[u8], tag: BerTag, f: F) -> IResult<&[u8], BerObject, u32>
where
    F: Fn(&[u8], BerTag, usize) -> IResult<&[u8], BerObjectContent, u32>,
{
    alt_complete! {
        i,
        do_parse!(
            hdr:     ber_read_element_header >>
            error_if!(hdr.tag != tag, ErrorKind::Custom(BER_TAG_ERROR)) >>
            content: map!(
                apply!(f, tag, hdr.len as usize),
                |b| { BerObject::from_obj(b) }
            ) >>
            (
                BerObject::from_header_and_content(
                    hdr,
                    BerObjectContent::ContextSpecific(tag,Some(Box::new(content)))
                )
            )
        ) |
        apply!(parse_ber_explicit_failed, tag)
    }
}

fn parse_ber_recursive(i: &[u8], depth: usize) -> IResult<&[u8], BerObject, u32> {
    error_if!(i, depth > MAX_RECURSION, ErrorKind::Custom(BER_MAX_DEPTH))?;
    let (rem, hdr) = ber_read_element_header(i)?;
    error_if!(
        i,
        hdr.len > ::std::u32::MAX as u64,
        ErrorKind::Custom(BER_INVALID_LENGTH)
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
        _    => { return Err(Err::Error(error_position!(i, ErrorKind::Custom(BER_CLASS_ERROR)))); },
    }
    match ber_read_element_content_as(rem, hdr.tag, hdr.len as usize, hdr.is_constructed(), depth) {
        Ok((rem, content)) => Ok((rem, BerObject::from_header_and_content(hdr, content))),
        Err(Err::Error(Context::Code(_, ErrorKind::Custom(BER_TAG_UNKNOWN)))) => {
            map!(rem, take!(hdr.len), |b| {
                BerObject::from_header_and_content(hdr, BerObjectContent::Unknown(hdr.tag, b))
            })
        }
        Err(e) => Err(e),
    }
}

/// Parse BER object
#[inline]
pub fn parse_ber(i: &[u8]) -> IResult<&[u8], BerObject, u32> {
    parse_ber_recursive(i, 0)
}
