use nom::{be_u8,IResult,Err,ErrorKind,Needed};
use rusticata_macros::bytes_to_u64;

use der::*;
use error::*;
use oid::Oid;




fn parse_identifier(i: &[u8]) -> IResult<&[u8],(u8,u8,u8)> {
    if i.is_empty() { IResult::Incomplete(Needed::Size(1)) }
    else {
        let a = i[0] >> 6;
        let b = if i[0] & 0b0010_0000 != 0 {1} else {0};
        let c = i[0] & 0b0001_1111;
        IResult::Done(&i[1..],(a,b,c))
    }
}

fn parse_der_length_byte(i: &[u8]) -> IResult<&[u8],(u8,u8)> {
    if i.is_empty() { IResult::Incomplete(Needed::Size(1)) }
    else {
        let a = i[0] >> 7;
        let b = i[0] & 0b0111_1111;
        IResult::Done(&i[1..],(a,b))
    }
}

/// Parse DER object and try to decode it as a 32-bits unsigned integer
pub fn parse_der_u32(i:&[u8]) -> IResult<&[u8],u32> {
    match parse_der_integer(i) {
        IResult::Done(rem,ref obj) => {
            match obj.content {
                DerObjectContent::Integer(i) => {
                    match i.len() {
                        1 => IResult::Done(rem, i[0] as u32),
                        2 => IResult::Done(rem, (i[0] as u32) << 8  | (i[1] as u32) ),
                        3 => IResult::Done(rem, (i[0] as u32) << 16 | (i[1] as u32) << 8 | (i[2] as u32) ),
                        4 => IResult::Done(rem, (i[0] as u32) << 24 | (i[1] as u32) << 16 | (i[2] as u32) << 8 | (i[3] as u32) ),
                        _ => IResult::Error(error_code!(ErrorKind::Custom(DER_INTEGER_TOO_LARGE))),
                    }
                }
                _ => IResult::Error(error_code!(ErrorKind::Custom(DER_TAG_ERROR))),
            }
        }
        IResult::Incomplete(i) => IResult::Incomplete(i),
        IResult::Error(e) => IResult::Error(e)
    }
}

/// Parse DER object and try to decode it as a 64-bits unsigned integer
pub fn parse_der_u64(i:&[u8]) -> IResult<&[u8],u64> {
    match parse_der_integer(i) {
        IResult::Done(rem,ref obj) => {
            match obj.content {
                DerObjectContent::Integer(i) => {
                    match bytes_to_u64(i) {
                        Ok(l)  => IResult::Done(rem, l),
                        Err(_) => IResult::Error(error_code!(ErrorKind::Custom(DER_INTEGER_TOO_LARGE))),
                    }
                }
                _ => IResult::Error(error_code!(ErrorKind::Custom(DER_TAG_ERROR))),
            }
        }
        IResult::Incomplete(i) => IResult::Incomplete(i),
        IResult::Error(e) => IResult::Error(e)
    }
}

fn der_read_oid(i: &[u8]) -> Result<Vec<u64>,u64> {
    let mut oid = Vec::new();
    let mut acc : u64;

    if i.is_empty() { return Err(0); };

    /* first element = X*40 + Y (See 8.19.4) */
    acc = i[0] as u64;
    oid.push( acc / 40);
    oid.push( acc % 40);

    acc = 0;
    for &c in &i[1..] {
        acc = (acc << 7) | (c & 0b0111_1111) as u64;
        if (c & (1<<7)) == 0 {
            oid.push(acc);
            acc = 0;
        }
    }

    match acc {
        0 => Ok(oid),
        _ => Err(acc),
    }
}


named!(pub der_read_element_header<&[u8],DerObjectHeader>,
    do_parse!(
        el:   parse_identifier >>
        len:  parse_der_length_byte >>
        llen: cond!(len.0 == 1, take!(len.1)) >>

        ( {
            let len : u64 = match len.0 {
                0 => len.1 as u64,
                _ => {
                    // XXX llen: test if 0 (indefinite form), if len is 0xff -> error
                    match bytes_to_u64(llen.unwrap()) {
                        Ok(l)  => l,
                        Err(_) => { return IResult::Error(error_code!(ErrorKind::Custom(DER_TAG_ERROR))); },
                    }
                },
            };
            DerObjectHeader {
                class: el.0,
                structured: el.1,
                tag: el.2,
                len,
            }
        } )
    )
);

named!(der_read_sequence_content<&[u8],Vec<DerObject> >,
    many0!(parse_der)
);

named!(der_read_set_content<&[u8],Vec<DerObject> >,
    many0!(parse_der)
);

/// Parse the next bytes as the content of a DER object.
///
/// Content type is *not* checked, caller is reponsible of providing the correct tag
pub fn der_read_element_content_as(i:&[u8], tag:u8, len:usize) -> IResult<&[u8], DerObjectContent> {
    match tag {
        // 0x00 end-of-content
        // 0x01 bool
        0x01 => {
            match be_u8(i) {
                IResult::Done(rem,0x00) => IResult::Done(rem,DerObjectContent::Boolean(false)),
                IResult::Done(rem,0xff) => IResult::Done(rem,DerObjectContent::Boolean(true)),
                IResult::Done(_,_)      => IResult::Error(error_code!(ErrorKind::Verify)),
                IResult::Error(e)       => IResult::Error(e),
                IResult::Incomplete(i)  => IResult::Incomplete(i),
            }
        },
        0x02 => {
                    map!(i,
                        take!(len),
                        |i| { DerObjectContent::Integer(i) }
                    )
                },
        // 0x03: bitstring
        0x03 => {
                    do_parse!(i,
                        ignored_bits: be_u8 >>
                                      error_if!(len == 0, ErrorKind::LengthValue) >>
                        s:            take!(len - 1) >> // XXX we must check if constructed or not (8.6.3)
                        ( DerObjectContent::BitString(ignored_bits,BitStringObject{ data:s }) )
                    )
                },
        // 0x04: octetstring
        0x04 => {
                    map!(i,
                        take!(len), // XXX we must check if constructed or not (8.7)
                        |s| { DerObjectContent::OctetString(s) }
                    )
                },
        // 0x05: null
        0x05 => { IResult::Done(i,DerObjectContent::Null) },
        // 0x06: object identified
        0x06 => {
                    do_parse!(i,
                             error_if!(len == 0, ErrorKind::LengthValue) >>
                        oid: map_res!(take!(len),der_read_oid) >>
                        ( DerObjectContent::OID(Oid::from(&oid)) )
                    )
                },
        // 0x0a: enumerated
        0x0a => {
                    map!(i,
                        parse_hex_to_u64!(len),
                        |i| { DerObjectContent::Enum(i) }
                    )
                },
        // 0x0c: UTF8String
        0x0c => {
                    map!(i,
                        take!(len), // XXX we must check if constructed or not (8.7)
                        |s| { DerObjectContent::UTF8String(s) }
                    )
                },
        // 0x10: sequence
        0x10 => {
                    map!(i,
                        flat_take!(len,der_read_sequence_content),
                        |l| { DerObjectContent::Sequence(l) }
                    )
                },
        // 0x11: set
        0x11 => {
                    map!(i,
                        flat_take!(len,der_read_set_content),
                        |l| { DerObjectContent::Set(l) }
                    )
                },
        // 0x12: numericstring
        0x12 => {
                    map!(i,
                        take!(len), // XXX we must check if constructed or not (8.7)
                        |s| { DerObjectContent::NumericString(s) }
                    )
                },
        // 0x13: printablestring
        0x13 => {
                    map!(i,
                        take!(len), // XXX we must check if constructed or not (8.7)
                        |s| { DerObjectContent::PrintableString(s) }
                    )
                },
        // 0x14: t61string
        0x14 => {
                    map!(i,
                        take!(len), // XXX we must check if constructed or not (8.7)
                        |s| { DerObjectContent::T61String(s) }
                    )
                },

        // 0x16: ia5string
        0x16 => {
                    map!(i,
                        take!(len), // XXX we must check if constructed or not (8.7)
                        |s| { DerObjectContent::IA5String(s) }
                    )
                },
        // 0x17: utctime
        0x17 => {
                    map!(i,
                        take!(len), // XXX we must check if constructed or not (8.7)
                        |s| { DerObjectContent::UTCTime(s) }
                    )
                },
        // 0x18: generalizedtime
        0x18 => {
                    map!(i,
                        take!(len), // XXX we must check if constructed or not (8.7)
                        |s| { DerObjectContent::GeneralizedTime(s) }
                    )
                },
                //
        // 0x1b: generalstring
        0x1b => {
                    map!(i,
                        take!(len), // XXX we must check if constructed or not (8.7)
                        |s| { DerObjectContent::GeneralString(s) }
                    )
                },
        // 0x1e: bmpstring
        0x1e => {
                    map!(i,
                        take!(len), // XXX we must check if constructed or not (8.7)
                        |s| { DerObjectContent::BmpString(s) }
                    )
                },
        // all unknown values
        _    => { IResult::Error(Err::Code(ErrorKind::Custom(DER_TAG_UNKNOWN))) },
    }
}


pub fn der_read_element_content(i: &[u8], hdr: DerObjectHeader) -> IResult<&[u8], DerObject> {
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
            |b| { DerObject::from_header_and_content(hdr,DerObjectContent::Unknown(b)) }
        ),
        _    => { return IResult::Error(Err::Code(ErrorKind::Custom(DER_CLASS_ERROR))); },
    }
    match der_read_element_content_as(i, hdr.tag, hdr.len as usize) {
        IResult::Done(rem,content) => {
            IResult::Done(rem, DerObject::from_header_and_content(hdr,content))
        },
        IResult::Error(Err::Code(ErrorKind::Custom(DER_TAG_UNKNOWN))) => {
            map!(i,
                 take!(hdr.len),
                 |b| { DerObject::from_header_and_content(hdr,DerObjectContent::Unknown(b)) }
            )
        }
        IResult::Error(e) => IResult::Error(e),
        IResult::Incomplete(e) => IResult::Incomplete(e),
    }
}

/// Read a boolean value
///
/// The encoding of a boolean value shall be primitive. The contents octets shall consist of a
/// single octet.
///
/// If the boolean value is FALSE, the octet shall be zero.
/// If the boolean value is TRUE, the octet shall be one byte, and have all bits set to one (0xff).
pub fn parse_der_bool(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.tag != DerTag::Boolean as u8, ErrorKind::Custom(DER_TAG_ERROR)) >>
                error_if!(hdr.len != 1, ErrorKind::Custom(DER_INVALID_LENGTH)) >>
       b:       verify!(be_u8, |b| b==0x00 || b==0xff) >>
       ( DerObject::from_header_and_content(hdr, DerObjectContent::Boolean(b != 0)) )
   )
}

/// Read an integer value
///
/// The encoding of a boolean value shall be primitive. The contents octets shall consist of one or
/// more octets.
///
/// To access the content, use the [`as_u64`](struct.DerObject.html#method.as_u64),
/// [`as_u32`](struct.DerObject.html#method.as_u32),
/// [`as_biguint`](struct.DerObject.html#method.as_biguint) or
/// [`as_bigint`](struct.DerObject.html#method.as_bigint) methods.
/// Remember that a DER integer has unlimited size, so these methods return `Result` or `Option`
/// objects.
///
/// # Examples
///
/// ```rust,no_run
/// # #[macro_use] extern crate der_parser;
/// # extern crate nom;
/// # use nom::IResult;
/// # use der_parser::parse_der_integer;
/// # use der_parser::{DerObject,DerObjectContent};
/// # fn main() {
/// let empty = &b""[..];
/// let bytes = [0x02, 0x03, 0x01, 0x00, 0x01];
/// let expected  = DerObject::from_obj(DerObjectContent::Integer(b"\x01\x00\x01"));
/// assert_eq!(
///     parse_der_integer(&bytes),
///     IResult::Done(empty, expected)
/// );
/// # }
/// ```
pub fn parse_der_integer(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.tag != DerTag::Integer as u8, ErrorKind::Custom(DER_TAG_ERROR)) >>
       content: take!(hdr.len) >>
       ( DerObject::from_header_and_content(hdr, DerObjectContent::Integer(content)) )
   )
}

pub fn parse_der_bitstring(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:          der_read_element_header >>
                     error_if!(hdr.tag != DerTag::BitString as u8, ErrorKind::Custom(DER_TAG_ERROR)) >>
       ignored_bits: be_u8 >>
                     error_if!(hdr.len < 1, ErrorKind::Custom(DER_INVALID_LENGTH)) >>
                     error_if!(hdr.is_constructed(), ErrorKind::Custom(DER_UNSUPPORTED)) >>
       content:      take!(hdr.len - 1) >> // XXX we must check if constructed or not (8.6.3)
       ( DerObject::from_header_and_content(hdr, DerObjectContent::BitString(ignored_bits,BitStringObject{data:content})) )
   )
}

pub fn parse_der_octetstring(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.tag != DerTag::OctetString as u8, ErrorKind::Custom(DER_TAG_ERROR)) >>
       content: take!(hdr.len) >> // XXX we must check if constructed or not (8.7)
       ( DerObject::from_header_and_content(hdr, DerObjectContent::OctetString(content)) )
   )
}

pub fn parse_der_null(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.tag != DerTag::Null as u8, ErrorKind::Custom(DER_TAG_ERROR)) >>
       ( DerObject::from_header_and_content(hdr, DerObjectContent::Null) )
   )
}

pub fn parse_der_oid(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.tag != DerTag::Oid as u8, ErrorKind::Custom(DER_TAG_ERROR)) >>
       content: map_res!(take!(hdr.len),der_read_oid) >>
       ( DerObject::from_header_and_content(hdr, DerObjectContent::OID(Oid::from(&content))) )
   )
}

pub fn parse_der_enum(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.tag != DerTag::Enumerated as u8, ErrorKind::Custom(DER_TAG_ERROR)) >>
       content: parse_hex_to_u64!(hdr.len) >>
       ( DerObject::from_header_and_content(hdr, DerObjectContent::Enum(content)) )
   )
}

pub fn parse_der_utf8string(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.tag != DerTag::Utf8String as u8, ErrorKind::Custom(DER_TAG_ERROR)) >>
       content: take!(hdr.len) >> // XXX we must check if constructed or not (8.7)
       ( DerObject::from_header_and_content(hdr, DerObjectContent::UTF8String(content)) )
   )
}

/// Parse a sequence of DER elements
///
/// Read a sequence of DER objects, without any constraint on the types.
/// Sequence is parsed recursively, so if structured elements are found, they are parsed using the
/// same function.
///
/// To read a specific sequence of objects (giving the expected types), use the
/// [`parse_der_sequence_defined`](macro.parse_der_sequence_defined.html) macro.
pub fn parse_der_sequence(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.tag != DerTag::Sequence as u8, ErrorKind::Custom(DER_TAG_ERROR)) >>
       content: flat_take!(hdr.len as usize,der_read_sequence_content) >>
       ( DerObject::from_header_and_content(hdr, DerObjectContent::Sequence(content)) )
   )
}

/// Parse a set of DER elements
///
/// Read a set of DER objects, without any constraint on the types.
/// Sequence is parsed recursively, so if structured elements are found, they are parsed using the
/// same function.
///
/// To read a specific set of objects (giving the expected types), use the
/// [`parse_der_set_defined`](macro.parse_der_set_defined.html) macro.
pub fn parse_der_set(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.tag != DerTag::Set as u8, ErrorKind::Custom(DER_TAG_ERROR)) >>
       content: flat_take!(hdr.len as usize,der_read_set_content) >>
       ( DerObject::from_header_and_content(hdr, DerObjectContent::Set(content)) )
   )
}

pub fn parse_der_numericstring(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.tag != DerTag::NumericString as u8, ErrorKind::Custom(DER_TAG_ERROR)) >>
       content: take!(hdr.len) >> // XXX we must check if constructed or not (8.7)
       ( DerObject::from_header_and_content(hdr, DerObjectContent::NumericString(content)) )
   )
}

pub fn parse_der_printablestring(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.tag != DerTag::PrintableString as u8, ErrorKind::Custom(DER_TAG_ERROR)) >>
       content: take!(hdr.len) >> // XXX we must check if constructed or not (8.7)
       ( DerObject::from_header_and_content(hdr, DerObjectContent::PrintableString(content)) )
   )
}

pub fn parse_der_ia5string(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.tag != DerTag::Ia5String as u8, ErrorKind::Custom(DER_TAG_ERROR)) >>
       content: take!(hdr.len) >> // XXX we must check if constructed or not (8.7)
       ( DerObject::from_header_and_content(hdr, DerObjectContent::IA5String(content)) )
   )
}

pub fn parse_der_t61string(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.tag != DerTag::T61String as u8, ErrorKind::Custom(DER_TAG_ERROR)) >>
       content: take!(hdr.len) >> // XXX we must check if constructed or not (8.7)
       ( DerObject::from_header_and_content(hdr, DerObjectContent::T61String(content)) )
   )
}

pub fn parse_der_bmpstring(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.tag != DerTag::BmpString as u8, ErrorKind::Custom(DER_TAG_ERROR)) >>
       content: take!(hdr.len) >> // XXX we must check if constructed or not (8.7)
       ( DerObject::from_header_and_content(hdr, DerObjectContent::BmpString(content)) )
   )
}

pub fn parse_der_utctime(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.tag != DerTag::UtcTime as u8, ErrorKind::Custom(DER_TAG_ERROR)) >>
       content: take!(hdr.len) >> // XXX we must check if constructed or not (8.7)
       ( DerObject::from_header_and_content(hdr, DerObjectContent::UTCTime(content)) )
   )
}

pub fn parse_der_generalizedtime(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.tag != DerTag::GeneralizedTime as u8, ErrorKind::Custom(DER_TAG_ERROR)) >>
       content: take!(hdr.len) >> // XXX we must check if constructed or not (8.7)
       ( DerObject::from_header_and_content(hdr, DerObjectContent::GeneralizedTime(content)) )
   )
}

pub fn parse_der_generalstring(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.tag != DerTag::GeneralString as u8, ErrorKind::Custom(DER_TAG_ERROR)) >>
       content: take!(hdr.len) >> // XXX we must check if constructed or not (8.7)
       ( DerObject::from_header_and_content(hdr, DerObjectContent::GeneralString(content)) )
   )
}

pub fn parse_der_explicit_failed(i:&[u8], tag: u8) -> IResult<&[u8],DerObject,u32> {
    value!(i,DerObject::from_obj(DerObjectContent::ContextSpecific(tag,None)))
}

pub fn parse_der_explicit<F>(i:&[u8], tag: u8, f:F) -> IResult<&[u8],DerObject,u32>
    where F: Fn(&[u8]) -> IResult<&[u8],DerObject,u32>
{
    alt_complete!(
        i,
        do_parse!(
            hdr:     der_read_element_header >>
            error_if!(hdr.tag != tag as u8, ErrorKind::Custom(DER_TAG_ERROR)) >>
            content: f >>
            (
                DerObject::from_header_and_content(
                    hdr,
                    DerObjectContent::ContextSpecific(tag,Some(Box::new(content)))
                )
            )
        ) |
        apply!(parse_der_explicit_failed,tag)
    )
}

/// call der *content* parsing function
pub fn parse_der_implicit<F>(i:&[u8], tag: u8, f:F) -> IResult<&[u8],DerObject,u32>
    where F: Fn(&[u8], u8, usize) -> IResult<&[u8],DerObjectContent,u32>
{
    alt_complete!(
        i,
        do_parse!(
            hdr:     der_read_element_header >>
            error_if!(hdr.tag != tag as u8, ErrorKind::Custom(DER_TAG_ERROR)) >>
            content: map!(
                apply!(f, tag, hdr.len as usize),
                |b| { DerObject::from_obj(b) }
            ) >>
            (
                DerObject::from_header_and_content(
                    hdr,
                    DerObjectContent::ContextSpecific(tag,Some(Box::new(content)))
                )
            )
        ) |
        apply!(parse_der_explicit_failed,tag)
    )
}


named!(pub parse_der<&[u8],DerObject>,
    do_parse!(
        hdr:     der_read_element_header >>
                 // XXX safety check: length cannot be more than 2^32 bytes
                 error_if!(hdr.len > ::std::u32::MAX as u64, ErrorKind::Custom(DER_INVALID_LENGTH)) >>
        content: apply!(der_read_element_content,hdr) >>
        ( content )
    )
);





#[cfg(test)]
mod tests {
    use der_parser::*;
    use nom::{IResult,Err,ErrorKind};

#[test]
fn test_der_bool() {
    let empty = &b""[..];
    let b_true  = DerObject::from_obj(DerObjectContent::Boolean(true));
    let b_false  = DerObject::from_obj(DerObjectContent::Boolean(false));
    assert_eq!(parse_der_bool(&[0x01, 0x01, 0x00]), IResult::Done(empty, b_false));
    assert_eq!(parse_der_bool(&[0x01, 0x01, 0xff]), IResult::Done(empty, b_true));
    assert_eq!(parse_der_bool(&[0x01, 0x01, 0x7f]), IResult::Error(error_position!(ErrorKind::Verify,&[0x7f][..])));
}

#[test]
fn test_der_int() {
    let empty = &b""[..];
    let bytes = [0x02, 0x03, 0x01, 0x00, 0x01];
    let expected  = DerObject::from_obj(DerObjectContent::Integer(b"\x01\x00\x01"));
    assert_eq!(parse_der_integer(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_int_as_u32() {
    let val  = DerObject::from_obj(DerObjectContent::Integer(b"\x01\x00\x01"));
    assert_eq!(val.content.as_u32(), Ok(65537));
    let val  = DerObject::from_obj(DerObjectContent::Integer(b"\x01\x00\x01\x00\x01"));
    assert_eq!(val.content.as_u32(), Err(DerError::IntegerTooLarge));
}

#[test]
fn test_der_int_long() {
    let empty = &b""[..];
    let bytes = [0x02, 0x0a, 0x39, 0x11, 0x45, 0x10, 0x94, 0x39, 0x11, 0x45, 0x10, 0x94];
    let expected  = DerObject::from_obj(DerObjectContent::Integer(&bytes[2..]));
    assert_eq!(parse_der_integer(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_octetstring() {
    let empty = &b""[..];
    let bytes = [ 0x04, 0x05,
                  0x41, 0x41, 0x41, 0x41, 0x41,
    ];
    let expected  = DerObject::from_obj(DerObjectContent::OctetString(b"AAAAA"));
    assert_eq!(parse_der_octetstring(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_null() {
    let empty = &b""[..];
    let expected  = DerObject::from_obj(DerObjectContent::Null);
    assert_eq!(parse_der_null(&[0x05, 0x00]), IResult::Done(empty, expected));
}

#[test]
fn test_der_oid() {
    let empty = &b""[..];
    let bytes = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05];
    let expected  = DerObject::from_obj(DerObjectContent::OID(Oid::from(&[1, 2, 840, 113549, 1, 1, 5])));
    assert_eq!(parse_der_oid(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_enum() {
    let empty = &b""[..];
    let expected  = DerObject::from_obj(DerObjectContent::Enum(2));
    assert_eq!(parse_der_enum(&[0x0a, 0x01, 0x02]), IResult::Done(empty, expected));
}

#[test]
fn test_der_utf8string() {
    let empty = &b""[..];
    let bytes = [ 0x0c, 0x0a,
                  0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65
    ];
    let expected  = DerObject::from_obj(DerObjectContent::UTF8String(b"Some-State"));
    assert_eq!(parse_der_utf8string(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_seq() {
    let empty = &b""[..];
    let bytes = [ 0x30, 0x05,
                  0x02, 0x03, 0x01, 0x00, 0x01,
    ];
    let expected  = DerObject::from_obj(DerObjectContent::Sequence(vec![
        DerObject::from_int_slice(b"\x01\x00\x01"),
    ]));
    assert_eq!(parse_der_sequence(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_set() {
    let empty = &b""[..];
    let bytes = [
        0x31, 0x05,
        0x02, 0x03, 0x01, 0x00, 0x01, // Integer 65537
    ];
    let expected  = DerObject::from_obj(DerObjectContent::Set(vec![
        DerObject::from_int_slice(b"\x01\x00\x01"),
    ]));
    assert_eq!(parse_der(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_set_defined() {
    let empty = &b""[..];
    let bytes = [ 0x31, 0x0a,
                  0x02, 0x03, 0x01, 0x00, 0x01,
                  0x02, 0x03, 0x01, 0x00, 0x00,
    ];
    let expected  = DerObject::from_obj(DerObjectContent::Set(vec![
        DerObject::from_int_slice(b"\x01\x00\x01"),
        DerObject::from_int_slice(b"\x01\x00\x00"),
    ]));
    fn parser(i:&[u8]) -> IResult<&[u8],DerObject> {
        parse_der_set_defined!(i,
            parse_der_integer,
            parse_der_integer
        )
    };
    assert_eq!(parser(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_seq_defined() {
    let empty = &b""[..];
    let bytes = [ 0x30, 0x0a,
                  0x02, 0x03, 0x01, 0x00, 0x01,
                  0x02, 0x03, 0x01, 0x00, 0x00,
    ];
    let expected  = DerObject::from_obj(DerObjectContent::Sequence(vec![
        DerObject::from_int_slice(b"\x01\x00\x01"),
        DerObject::from_int_slice(b"\x01\x00\x00"),
    ]));
    fn parser(i:&[u8]) -> IResult<&[u8],DerObject> {
        parse_der_sequence_defined!(i,
            parse_der_integer,
            parse_der_integer
        )
    };
    assert_eq!(parser(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_seq_of() {
    let empty = &b""[..];
    let bytes = [ 0x30, 0x0a,
                  0x02, 0x03, 0x01, 0x00, 0x01,
                  0x02, 0x03, 0x01, 0x00, 0x00,
    ];
    let expected  = DerObject::from_obj(DerObjectContent::Sequence(vec![
        DerObject::from_int_slice(b"\x01\x00\x01"),
        DerObject::from_int_slice(b"\x01\x00\x00"),
    ]));
    fn parser(i:&[u8]) -> IResult<&[u8],DerObject> {
        parse_der_sequence_of!(i, parse_der_integer)
    };
    assert_eq!(parser(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_seq_of_incomplete() {
    let bytes = [ 0x30, 0x07,
                  0x02, 0x03, 0x01, 0x00, 0x01,
                  0x00, 0x00,
    ];
    fn parser(i:&[u8]) -> IResult<&[u8],DerObject> {
        parse_der_sequence_of!(i, parse_der_integer)
    };
    assert_eq!(parser(&bytes), IResult::Error(Err::Position(ErrorKind::Eof, &bytes[7..])));
}

#[test]
fn test_der_set_of() {
    let empty = &b""[..];
    let bytes = [ 0x31, 0x0a,
                  0x02, 0x03, 0x01, 0x00, 0x01,
                  0x02, 0x03, 0x01, 0x00, 0x00,
    ];
    let expected  = DerObject::from_obj(DerObjectContent::Set(vec![
        DerObject::from_int_slice(b"\x01\x00\x01"),
        DerObject::from_int_slice(b"\x01\x00\x00"),
    ]));
    fn parser(i:&[u8]) -> IResult<&[u8],DerObject> {
        parse_der_set_of!(i, parse_der_integer)
    };
    assert_eq!(parser(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_utctime() {
    let empty = &b""[..];
    let bytes = [0x17, 0x0D, 0x30, 0x32, 0x31, 0x32, 0x31, 0x33, 0x31, 0x34, 0x32, 0x39, 0x32, 0x33, 0x5A ];
    let expected = DerObject{
        class: 0,
        structured: 0,
        tag: DerTag::UtcTime as u8,
        content: DerObjectContent::UTCTime(&bytes[2..]),
    };
    assert_eq!(parse_der(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_generalizedtime() {
    let empty = &b""[..];
    let bytes = [0x18, 0x0D, 0x30, 0x32, 0x31, 0x32, 0x31, 0x33, 0x31, 0x34, 0x32, 0x39, 0x32, 0x33, 0x5A ];
    let expected = DerObject{
        class: 0,
        structured: 0,
        tag: DerTag::GeneralizedTime as u8,
        content: DerObjectContent::GeneralizedTime(&bytes[2..]),
    };
    assert_eq!(parse_der_generalizedtime(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_generalstring() {
    let empty = &b""[..];
    let bytes = [ 0x1b, 0x04,
                  0x63, 0x69, 0x66, 0x73
    ];
    let expected  = DerObject::from_obj(DerObjectContent::GeneralString(b"cifs"));
    assert_eq!(parse_der_generalstring(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_contextspecific() {
    let bytes = [0xa0, 0x03, 0x02, 0x01, 0x02];
    let empty = &b""[..];
    let expected = DerObject{
        class: 2,
        structured: 1,
        tag: 0,
        content: DerObjectContent::Unknown(&bytes[2..]),
    };
    assert_eq!(parse_der(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_explicit() {
    let empty = &b""[..];
    let bytes = [0xa0, 0x03, 0x02, 0x01, 0x02];
    let expected = DerObject{
        class: 2,
        structured: 1,
        tag: 0,
        content: DerObjectContent::ContextSpecific(0,Some(Box::new(DerObject::from_int_slice(b"\x02")))),
    };
    assert_eq!(parse_der_explicit(&bytes, 0, parse_der_integer), IResult::Done(empty, expected));
    let expected2 = DerObject::from_obj(DerObjectContent::ContextSpecific(1,None));
    assert_eq!(parse_der_explicit(&bytes, 1, parse_der_integer), IResult::Done(&bytes[..], expected2));
}

#[test]
fn test_der_implicit() {
    let empty = &b""[..];
    let bytes = [0x81, 0x04, 0x70, 0x61, 0x73, 0x73];
    let pass = DerObject::from_obj(DerObjectContent::IA5String(b"pass"));
    let expected = DerObject{
        class: 2,
        structured: 0,
        tag: 1,
        content: DerObjectContent::ContextSpecific(1,Some(Box::new(pass))),
    };
    fn der_read_ia5string_content(i:&[u8], _tag:u8, len: usize) -> IResult<&[u8],DerObjectContent,u32> {
        der_read_element_content_as(i, DerTag::Ia5String as u8, len)
    }
    assert_eq!(parse_der_implicit(&bytes, 1, der_read_ia5string_content), IResult::Done(empty, expected));
    let expected2 = DerObject::from_obj(DerObjectContent::ContextSpecific(2,None));
    assert_eq!(parse_der_implicit(&bytes, 2, der_read_ia5string_content), IResult::Done(&bytes[..], expected2));
}

#[test]
fn test_der_optional() {
    let empty = &b""[..];
    let bytes1 = [ 0x30, 0x0a,
                  0x0a, 0x03, 0x00, 0x00, 0x01,
                  0x02, 0x03, 0x01, 0x00, 0x01,
    ];
    let bytes2 = [ 0x30, 0x05,
                  0x02, 0x03, 0x01, 0x00, 0x01,
    ];
    let expected1  = DerObject::from_obj(DerObjectContent::Sequence(vec![
        DerObject::from_obj(
            DerObjectContent::ContextSpecific(0, Some(Box::new(DerObject::from_obj(DerObjectContent::Enum(1)))))
        ),
        DerObject::from_int_slice(b"\x01\x00\x01"),
    ]));
    let expected2  = DerObject::from_obj(DerObjectContent::Sequence(vec![
        DerObject::from_obj(
            DerObjectContent::ContextSpecific(0, None),
        ),
        DerObject::from_int_slice(b"\x01\x00\x01"),
    ]));
    fn parse_optional_enum(i:&[u8]) -> IResult<&[u8],DerObject> {
        parse_der_optional!(i, parse_der_enum)
    }
    fn parser(i:&[u8]) -> IResult<&[u8],DerObject> {
        parse_der_sequence_defined!(i,
            parse_optional_enum,
            parse_der_integer
        )
    };
    assert_eq!(parser(&bytes1), IResult::Done(empty, expected1));
    assert_eq!(parser(&bytes2), IResult::Done(empty, expected2));
}

#[test]
fn test_der_seq_dn() {
    let empty = &b""[..];
    let bytes = [
        0x30, 0x45, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
        0x02, 0x46, 0x52, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08,
        0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65,
        0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49,
        0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67,
        0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64
    ];
    let expected = DerObject::from_obj(
        DerObjectContent::Sequence(
            vec![
                DerObject::from_obj(DerObjectContent::Set(vec![
                    DerObject::from_obj(DerObjectContent::Sequence(vec![
                        DerObject::from_obj(DerObjectContent::OID(Oid::from(&[2, 5, 4, 6]))), // countryName
                        DerObject::from_obj(DerObjectContent::PrintableString(b"FR")),
                    ])),
                ])),
                DerObject::from_obj(DerObjectContent::Set(vec![
                    DerObject::from_obj(DerObjectContent::Sequence(vec![
                        DerObject::from_obj(DerObjectContent::OID(Oid::from(&[2, 5, 4, 8]))), // stateOrProvinceName
                        DerObject::from_obj(DerObjectContent::UTF8String(b"Some-State")),
                    ])),
                ])),
                DerObject::from_obj(DerObjectContent::Set(vec![
                    DerObject::from_obj(DerObjectContent::Sequence(vec![
                        DerObject::from_obj(DerObjectContent::OID(Oid::from(&[2, 5, 4, 10]))), // organizationName
                        DerObject::from_obj(DerObjectContent::UTF8String(b"Internet Widgits Pty Ltd")),
                    ])),
                ])),
            ]
        )
    );
    assert_eq!(parse_der(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_seq_dn_defined() {
    let empty = &b""[..];
    let bytes = [
        0x30, 0x45, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
        0x02, 0x46, 0x52, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08,
        0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65,
        0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49,
        0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67,
        0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64
    ];
    let expected = DerObject::from_obj(
        DerObjectContent::Sequence(
            vec![
                DerObject::from_obj(DerObjectContent::Set(vec![
                    DerObject::from_obj(DerObjectContent::Sequence(vec![
                        DerObject::from_obj(DerObjectContent::OID(Oid::from(&[2, 5, 4, 6]))), // countryName
                        DerObject::from_obj(DerObjectContent::PrintableString(b"FR")),
                    ])),
                ])),
                DerObject::from_obj(DerObjectContent::Set(vec![
                    DerObject::from_obj(DerObjectContent::Sequence(vec![
                        DerObject::from_obj(DerObjectContent::OID(Oid::from(&[2, 5, 4, 8]))), // stateOrProvinceName
                        DerObject::from_obj(DerObjectContent::UTF8String(b"Some-State")),
                    ])),
                ])),
                DerObject::from_obj(DerObjectContent::Set(vec![
                    DerObject::from_obj(DerObjectContent::Sequence(vec![
                        DerObject::from_obj(DerObjectContent::OID(Oid::from(&[2, 5, 4, 10]))), // organizationName
                        DerObject::from_obj(DerObjectContent::UTF8String(b"Internet Widgits Pty Ltd")),
                    ])),
                ])),
            ]
        )
    );
    #[inline]
    fn parse_directory_string(i:&[u8]) -> IResult<&[u8],DerObject> {
        alt!(i, parse_der_utf8string | parse_der_printablestring | parse_der_ia5string)
    }
    #[inline]
    fn parse_attr_type_and_value(i:&[u8]) -> IResult<&[u8],DerObject> {
        parse_der_sequence_defined!(i,
            parse_der_oid,
            parse_directory_string
        )
    };
    #[inline]
    fn parse_rdn(i:&[u8]) -> IResult<&[u8],DerObject> {
        parse_der_set_defined!(i, parse_attr_type_and_value)
    }
    #[inline]
    fn parse_name(i:&[u8]) -> IResult<&[u8],DerObject> {
        parse_der_sequence_defined!(i,
            parse_rdn,
            parse_rdn,
            parse_rdn
        )
    }
    assert_eq!(parse_name(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_defined_seq_macros() {
    fn localparse_seq(i:&[u8]) -> IResult<&[u8],DerObject> {
        parse_der_sequence_defined_m!(i,
            parse_der_integer >>
            call!(parse_der_integer)
        )
    }
    let empty = &b""[..];
    let bytes = [ 0x30, 0x0a,
                  0x02, 0x03, 0x01, 0x00, 0x01,
                  0x02, 0x03, 0x01, 0x00, 0x00,
    ];
    let expected  = DerObject::from_obj(DerObjectContent::Sequence(vec![
        DerObject::from_int_slice(b"\x01\x00\x01"),
        DerObject::from_int_slice(b"\x01\x00\x00"),
    ]));
    assert_eq!(localparse_seq(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_defined_set_macros() {
    fn localparse_set(i:&[u8]) -> IResult<&[u8],DerObject> {
        parse_der_set_defined_m!(i,
            parse_der_integer >>
            call!(parse_der_integer)
        )
    }
    let empty = &b""[..];
    let bytes = [ 0x31, 0x0a,
                  0x02, 0x03, 0x01, 0x00, 0x01,
                  0x02, 0x03, 0x01, 0x00, 0x00,
    ];
    let expected  = DerObject::from_obj(DerObjectContent::Set(vec![
        DerObject::from_int_slice(b"\x01\x00\x01"),
        DerObject::from_int_slice(b"\x01\x00\x00"),
    ]));
    assert_eq!(localparse_set(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_parse_u32() {
    let empty = &b""[..];
    assert_eq!(parse_der_u32(&[0x02, 0x01, 0x01]),IResult::Done(empty,1));
    assert_eq!(parse_der_u32(&[0x02, 0x01, 0xff]),IResult::Done(empty,255));
    assert_eq!(parse_der_u32(&[0x02, 0x02, 0x01, 0x23]),IResult::Done(empty,0x123));
    assert_eq!(parse_der_u32(&[0x02, 0x02, 0xff, 0xff]),IResult::Done(empty,0xffff));
    assert_eq!(parse_der_u32(&[0x02, 0x03, 0x01, 0x23, 0x45]),IResult::Done(empty,0x12345));
    assert_eq!(parse_der_u32(&[0x02, 0x03, 0xff, 0xff, 0xff]),IResult::Done(empty,0xffffff));
    assert_eq!(parse_der_u32(&[0x02, 0x04, 0x01, 0x23, 0x45, 0x67]),IResult::Done(empty,0x1234567));
    assert_eq!(parse_der_u32(&[0x02, 0x04, 0xff, 0xff, 0xff, 0xff]),IResult::Done(empty,0xffffffff));
    assert_eq!(parse_der_u32(&[0x02, 0x05, 0x01, 0x23, 0x45, 0x67, 0x89]),IResult::Error(error_code!(ErrorKind::Custom(DER_INTEGER_TOO_LARGE))));
    let s = &[0x01, 0x01, 0xff];
    assert_eq!(parse_der_u32(s),IResult::Error(error_position!(ErrorKind::Custom(DER_TAG_ERROR), &s[2..])));
}

#[test]
fn test_parse_u64() {
    let empty = &b""[..];
    assert_eq!(parse_der_u64(&[0x02, 0x01, 0x01]),IResult::Done(empty,1));
    assert_eq!(parse_der_u64(&[0x02, 0x01, 0xff]),IResult::Done(empty,255));
    assert_eq!(parse_der_u64(&[0x02, 0x02, 0x01, 0x23]),IResult::Done(empty,0x123));
    assert_eq!(parse_der_u64(&[0x02, 0x02, 0xff, 0xff]),IResult::Done(empty,0xffff));
    assert_eq!(parse_der_u64(&[0x02, 0x03, 0x01, 0x23, 0x45]),IResult::Done(empty,0x12345));
    assert_eq!(parse_der_u64(&[0x02, 0x03, 0xff, 0xff, 0xff]),IResult::Done(empty,0xffffff));
    assert_eq!(parse_der_u64(&[0x02, 0x04, 0x01, 0x23, 0x45, 0x67]),IResult::Done(empty,0x1234567));
    assert_eq!(parse_der_u64(&[0x02, 0x04, 0xff, 0xff, 0xff, 0xff]),IResult::Done(empty,0xffffffff));
    assert_eq!(parse_der_u64(&[0x02, 0x05, 0x01, 0x23, 0x45, 0x67, 0x89]),IResult::Done(empty,0x123456789));
    let s = &[0x01, 0x01, 0xff];
    assert_eq!(parse_der_u64(s),IResult::Error(error_position!(ErrorKind::Custom(DER_TAG_ERROR), &s[2..])));
}

}

