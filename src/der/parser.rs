use crate::ber::*;
use crate::error::*;
use der::DerObject;
use nom::{be_u8, Context, Err, ErrorKind, IResult};

/// Parse DER object
pub fn parse_der(i: &[u8]) -> IResult<&[u8], DerObject, u32> {
    do_parse! {
        i,
        hdr:     ber_read_element_header >>
                 // XXX safety check: length cannot be more than 2^32 bytes
                 error_if!(hdr.len > ::std::u32::MAX as u64, ErrorKind::Custom(BER_INVALID_LENGTH)) >>
        content: apply!(der_read_element_content,hdr) >>
        ( content )
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! der_constraint_fail_if(
    ($cond:expr, $slice:expr, $error:expr) => (
        {
            if $cond {
                return Err(::nom::Err::Error(error_position!($slice, ErrorKind::Custom($error))));
            }
        }
    );
);

/// Read a boolean value
///
/// The encoding of a boolean value shall be primitive. The contents octets shall consist of a
/// single octet.
///
/// If the boolean value is FALSE, the octet shall be zero.
/// If the boolean value is TRUE, the octet shall be one byte, and have all bits set to one (0xff).
pub fn parse_der_bool(i: &[u8]) -> IResult<&[u8], DerObject> {
    do_parse! {
        i,
        hdr:     ber_read_element_header >>
                 error_if!(hdr.tag != BerTag::Boolean, ErrorKind::Custom(BER_TAG_ERROR)) >>
                 error_if!(hdr.len != 1, ErrorKind::Custom(BER_INVALID_LENGTH)) >>
        b:       der_read_content_bool >>
        ( DerObject::from_header_and_content(hdr, b) )
    }
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
/// # use der_parser::der::{parse_der_integer, DerObject};
/// # use der_parser::ber::BerObjectContent;
/// # fn main() {
/// let empty = &b""[..];
/// let bytes = [0x02, 0x03, 0x01, 0x00, 0x01];
/// let expected  = DerObject::from_obj(BerObjectContent::Integer(b"\x01\x00\x01"));
/// assert_eq!(
///     parse_der_integer(&bytes),
///     Ok((empty, expected))
/// );
/// # }
/// ```
#[inline]
pub fn parse_der_integer(i: &[u8]) -> IResult<&[u8], DerObject> {
    parse_ber_integer(i)
}

pub fn parse_der_bitstring(i: &[u8]) -> IResult<&[u8], DerObject> {
    do_parse! {
        i,
        hdr: der_read_element_header >>
             error_if!(hdr.tag != BerTag::BitString, ErrorKind::Custom(BER_TAG_ERROR)) >>
             error_if!(hdr.is_constructed(), ErrorKind::Custom(DER_CONSTRAINT_FAIL)) >>
        b:   apply!(der_read_content_bitstring, hdr.len as usize) >>
        ( DerObject::from_header_and_content(hdr, b) )
    }
}

#[inline]
pub fn parse_der_octetstring(i: &[u8]) -> IResult<&[u8], DerObject> {
    parse_ber_octetstring(i)
}

#[inline]
pub fn parse_der_null(i: &[u8]) -> IResult<&[u8], DerObject> {
    parse_ber_null(i)
}

#[inline]
pub fn parse_der_oid(i: &[u8]) -> IResult<&[u8], DerObject> {
    parse_ber_oid(i)
}

#[inline]
pub fn parse_der_enum(i: &[u8]) -> IResult<&[u8], DerObject> {
    parse_ber_enum(i)
}

#[inline]
pub fn parse_der_utf8string(i: &[u8]) -> IResult<&[u8], DerObject> {
    parse_ber_utf8string(i)
}

#[inline]
pub fn parse_der_relative_oid(i: &[u8]) -> IResult<&[u8], DerObject> {
    parse_ber_relative_oid(i)
}

#[inline]
pub fn parse_der_sequence(i: &[u8]) -> IResult<&[u8], DerObject> {
    parse_ber_sequence(i)
}

#[inline]
pub fn parse_der_set(i: &[u8]) -> IResult<&[u8], DerObject> {
    parse_ber_set(i)
}

#[inline]
pub fn parse_der_numericstring(i: &[u8]) -> IResult<&[u8], DerObject> {
    parse_ber_numericstring(i)
}

#[inline]
pub fn parse_der_printablestring(i: &[u8]) -> IResult<&[u8], DerObject> {
    parse_ber_printablestring(i)
}

#[inline]
pub fn parse_der_t61string(i: &[u8]) -> IResult<&[u8], DerObject> {
    parse_ber_t61string(i)
}

#[inline]
pub fn parse_der_ia5string(i: &[u8]) -> IResult<&[u8], DerObject> {
    parse_ber_ia5string(i)
}

#[inline]
pub fn parse_der_utctime(i: &[u8]) -> IResult<&[u8], DerObject> {
    parse_ber_utctime(i)
}

#[inline]
pub fn parse_der_generalizedtime(i: &[u8]) -> IResult<&[u8], DerObject> {
    parse_ber_generalizedtime(i)
}

#[inline]
pub fn parse_der_generalstring(i: &[u8]) -> IResult<&[u8], DerObject> {
    parse_ber_generalstring(i)
}

#[inline]
pub fn parse_der_bmpstring(i: &[u8]) -> IResult<&[u8], DerObject> {
    parse_ber_bmpstring(i)
}

#[inline]
pub fn parse_der_explicit<F>(i: &[u8], tag: BerTag, f: F) -> IResult<&[u8], DerObject, u32>
where
    F: Fn(&[u8]) -> IResult<&[u8], DerObject, u32>,
{
    parse_ber_explicit(i, tag, f)
}

#[inline]
pub fn parse_der_implicit<F>(i: &[u8], tag: BerTag, f: F) -> IResult<&[u8], DerObject, u32>
where
    F: Fn(&[u8], BerTag, usize) -> IResult<&[u8], BerObjectContent, u32>,
{
    parse_ber_implicit(i, tag, f)
}

/// Parse DER object and try to decode it as a 32-bits unsigned integer
pub fn parse_der_u32(i: &[u8]) -> IResult<&[u8], u32> {
    match parse_ber_integer(i) {
        Ok((rem, ref obj)) => match obj.content {
            BerObjectContent::Integer(i) => match i.len() {
                1 => Ok((rem, i[0] as u32)),
                2 => Ok((rem, (i[0] as u32) << 8 | (i[1] as u32))),
                3 => Ok((
                    rem,
                    (i[0] as u32) << 16 | (i[1] as u32) << 8 | (i[2] as u32),
                )),
                4 => Ok((
                    rem,
                    (i[0] as u32) << 24 | (i[1] as u32) << 16 | (i[2] as u32) << 8 | (i[3] as u32),
                )),
                _ => Err(Err::Error(error_position!(
                    i,
                    ErrorKind::Custom(BER_INTEGER_TOO_LARGE)
                ))),
            },
            _ => Err(Err::Error(error_position!(
                i,
                ErrorKind::Custom(BER_TAG_ERROR)
            ))),
        },
        Err(e) => Err(e),
    }
}

/// Parse DER object and try to decode it as a 64-bits unsigned integer
pub fn parse_der_u64(i: &[u8]) -> IResult<&[u8], u64> {
    match parse_ber_integer(i) {
        Ok((rem, ref obj)) => match obj.content {
            BerObjectContent::Integer(i) => match bytes_to_u64(i) {
                Ok(l) => Ok((rem, l)),
                Err(_) => Err(Err::Error(error_position!(
                    i,
                    ErrorKind::Custom(BER_INTEGER_TOO_LARGE)
                ))),
            },
            _ => Err(Err::Error(error_position!(
                i,
                ErrorKind::Custom(BER_TAG_ERROR)
            ))),
        },
        Err(e) => Err(e),
    }
}

// --------- end of parse_der_xxx functions ----------

/// Parse the next bytes as the content of a DER object.
///
/// Content type is *not* checked, caller is reponsible of providing the correct tag
pub fn der_read_element_content_as(i:&[u8], tag:BerTag, len:usize) -> IResult<&[u8], BerObjectContent> {
    match tag {
        // 0x00 end-of-content
        BerTag::EndOfContent => ber_read_content_eoc(i),
        // 0x01 bool
        BerTag::Boolean => der_read_content_bool(i),
        // 0x02
        BerTag::Integer => ber_read_content_integer(i, len),
        // 0x03: bitstring
        BerTag::BitString => der_read_content_bitstring(i, len),
        // 0x04: octetstring
        BerTag::OctetString => ber_read_content_octetstring(i, len),
        // 0x05: null
        BerTag::Null => ber_read_content_null(i),
        // 0x06: object identified
        BerTag::Oid => ber_read_content_oid(i, len),
        // 0x0a: enumerated
        BerTag::Enumerated => ber_read_content_enum(i, len),
        // 0x0c: UTF8String
        BerTag::Utf8String => ber_read_content_utf8string(i, len),
        // 0x0d: relative object identified
        BerTag::RelativeOid => ber_read_content_relativeoid(i, len),
        // 0x10: sequence
        BerTag::Sequence => ber_read_content_sequence(i, len),
        // 0x11: set
        BerTag::Set => ber_read_content_set(i, len),
        // 0x12: numericstring
        BerTag::NumericString => ber_read_content_numericstring(i, len),
        // 0x13: printablestring
        BerTag::PrintableString => ber_read_content_printablestring(i, len),
        // 0x14: t61string
        BerTag::T61String => ber_read_content_t61string(i, len),
        // 0x16: ia5string
        BerTag::Ia5String => ber_read_content_ia5string(i, len),
        // 0x17: utctime
        BerTag::UtcTime => ber_read_content_utctime(i, len),
        // 0x18: generalizedtime
        BerTag::GeneralizedTime => ber_read_content_generalizedtime(i, len),
        // 0x1b: generalstring
        BerTag::GeneralString => ber_read_content_generalstring(i, len),
        // 0x1e: bmpstring
        BerTag::BmpString => ber_read_content_bmpstring(i, len),
        // all unknown values
        _    => { Err(Err::Error(error_position!(i, ErrorKind::Custom(BER_TAG_UNKNOWN)))) },
    }
}


pub fn der_read_element_content(i: &[u8], hdr: BerObjectHeader) -> IResult<&[u8], DerObject> {
    match hdr.class {
        // universal
        0b00 |
        // private
        0b11 => (),
        // application
        0b01 |
        // context-specific
        0b10 => return map!(
            i,
            take!(hdr.len),
            |b| { DerObject::from_header_and_content(hdr,BerObjectContent::Unknown(b)) }
        ),
        _    => { return Err(Err::Error(error_position!(i, ErrorKind::Custom(BER_CLASS_ERROR)))); },
    }
    match der_read_element_content_as(i, hdr.tag, hdr.len as usize) {
        Ok((rem,content)) => {
            Ok((rem, DerObject::from_header_and_content(hdr,content)))
        },
        Err(Err::Error(Context::Code(_, ErrorKind::Custom(BER_TAG_UNKNOWN)))) => {
            map!(i,
                 take!(hdr.len),
                 |b| { DerObject::from_header_and_content(hdr,BerObjectContent::Unknown(b)) }
            )
        }
        Err(e) => Err(e)
    }
}

#[inline]
fn der_read_content_bool(i: &[u8]) -> IResult<&[u8], BerObjectContent> {
    match be_u8(i) {
        Ok((rem, 0x00)) => Ok((rem, BerObjectContent::Boolean(false))),
        Ok((rem, 0xff)) => Ok((rem, BerObjectContent::Boolean(true))),
        Ok((_, _)) => Err(Err::Error(error_position!(
            i,
            ErrorKind::Custom(DER_CONSTRAINT_FAIL)
        ))),
        Err(e) => Err(e),
    }
}

#[inline]
fn der_read_content_bitstring(i: &[u8], len: usize) -> IResult<&[u8], BerObjectContent> {
    do_parse! {
        i,
        ignored_bits: be_u8 >>
                      error_if!(ignored_bits > 7, ErrorKind::Custom(DER_CONSTRAINT_FAIL)) >>
                      error_if!(len == 0, ErrorKind::Custom(BER_INVALID_LENGTH)) >>
        s:            take!(len - 1) >>
                      call!(|input| {
                          if len > 1 {
                              let mut last_byte = s[len-2];
                              for _ in 0..ignored_bits as usize {
                                  der_constraint_fail_if!(last_byte & 1 != 0, i, DER_CONSTRAINT_FAIL);
                                  last_byte >>= 1;
                              }
                          }
                          Ok((input,()))
                      }) >>
        ( BerObjectContent::BitString(ignored_bits,BitStringObject{ data:s }) )
    }
}

/// Read an object header (DER)
pub fn der_read_element_header(i: &[u8]) -> IResult<&[u8], BerObjectHeader> {
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
                    der_constraint_fail_if!(len.1 == 0b0111_1111, &i[1..], BER_INVALID_LENGTH);
                    // if len.1 == 0b0111_1111 {
                    //     return Err(::nom::Err::Error(error_position!(&i[1..], ErrorKind::Custom(BER_INVALID_LENGTH))));
                    // }
                    // DER(9.1) if len is 0 (indefinite form), obj must be constructed
                    der_constraint_fail_if!(len.1 == 0 && el.1 != 1, &i[1..], DER_CONSTRAINT_FAIL);
                    // if len.1 == 0 && el.1 != 1 {
                    //     return Err(::nom::Err::Error(error_position!(&i[1..], ErrorKind::Custom(BER_INVALID_LENGTH))));
                    // }
                    let llen = llen.unwrap(); // safe because we tested len.0 != 0
                    match bytes_to_u64(llen) {
                        Ok(l)  => {
                            // DER: should have been encoded in short form (< 127)
                            der_constraint_fail_if!(l < 127, i, DER_CONSTRAINT_FAIL);
                            l
                        },
                        Err(_) => { return Err(::nom::Err::Error(error_position!(llen, ErrorKind::Custom(BER_TAG_ERROR)))); },
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
