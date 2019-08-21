#[macro_use]
extern crate pretty_assertions;

extern crate der_parser;

#[macro_use]
extern crate nom;

use der_parser::ber::*;
use der_parser::error::*;
use der_parser::*;
use nom::error::ErrorKind;
use nom::Err;
use oid::Oid;

#[derive(Debug, PartialEq)]
struct MyStruct<'a> {
    a: BerObject<'a>,
    b: BerObject<'a>,
}

fn parse_struct01(i: &[u8]) -> BerResult<(BerObjectHeader, MyStruct)> {
    parse_der_struct!(
        i,
        a: parse_ber_integer >> b: parse_ber_integer >> (MyStruct { a: a, b: b })
    )
}

fn parse_struct01_complete(i: &[u8]) -> BerResult<(BerObjectHeader, MyStruct)> {
    parse_der_struct!(
        i,
        a: parse_ber_integer >> b: parse_ber_integer >> eof!() >> (MyStruct { a: a, b: b })
    )
}

// calling user function
#[allow(dead_code)]
fn parse_struct02(i: &[u8]) -> BerResult<(BerObjectHeader, ())> {
    parse_der_struct!(i, _a: parse_ber_integer >> _b: parse_struct01 >> (()))
}

// embedded DER structs
#[allow(dead_code)]
fn parse_struct03(i: &[u8]) -> BerResult<(BerObjectHeader, ())> {
    parse_der_struct!(
        i,
        _a: parse_ber_integer >> _b: parse_der_struct!(parse_ber_integer >> (())) >> (())
    )
}

// verifying tag
fn parse_struct04(i: &[u8], tag: BerTag) -> BerResult<(BerObjectHeader, MyStruct)> {
    parse_der_struct!(
        i,
        TAG tag,
        a: parse_ber_integer >>
        b: parse_ber_integer >>
           eof!() >>
        ( MyStruct{ a: a, b: b } )
    )
}

#[test]
fn struct01() {
    let bytes = [
        0x30, 0x0a, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x03, 0x01, 0x00, 0x00,
    ];
    let empty = &b""[..];
    let expected = (
        BerObjectHeader {
            class: 0,
            structured: 1,
            tag: BerTag::Sequence,
            len: 0xa,
        },
        MyStruct {
            a: BerObject::from_int_slice(b"\x01\x00\x01"),
            b: BerObject::from_int_slice(b"\x01\x00\x00"),
        },
    );
    let res = parse_struct01(&bytes);
    assert_eq!(res, Ok((empty, expected)));
}

#[test]
fn struct02() {
    let empty = &b""[..];
    let bytes = [
        0x30, 0x45, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x46, 0x52,
        0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65,
        0x2d, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a,
        0x0c, 0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67,
        0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64,
    ];
    #[derive(Debug, PartialEq)]
    struct Attr<'a> {
        oid: Oid,
        val: BerObject<'a>,
    };
    #[derive(Debug, PartialEq)]
    struct Rdn<'a> {
        a: Attr<'a>,
    }
    #[derive(Debug, PartialEq)]
    struct Name<'a> {
        l: Vec<Rdn<'a>>,
    }
    let expected = Name {
        l: vec![
            Rdn {
                a: Attr {
                    oid: Oid::from(&[2, 5, 4, 6]), // countryName
                    val: BerObject::from_obj(BerObjectContent::PrintableString(b"FR")),
                },
            },
            Rdn {
                a: Attr {
                    oid: Oid::from(&[2, 5, 4, 8]), // stateOrProvinceName
                    val: BerObject::from_obj(BerObjectContent::UTF8String(b"Some-State")),
                },
            },
            Rdn {
                a: Attr {
                    oid: Oid::from(&[2, 5, 4, 10]), // organizationName
                    val: BerObject::from_obj(BerObjectContent::UTF8String(
                        b"Internet Widgits Pty Ltd",
                    )),
                },
            },
        ],
    };
    fn parse_directory_string(i: &[u8]) -> BerResult {
        alt!(
            i,
            parse_ber_utf8string | parse_ber_printablestring | parse_ber_ia5string
        )
    }
    fn parse_attr_type_and_value(i: &[u8]) -> BerResult<Attr> {
        parse_der_struct!(
            i,
            o: map_res!(parse_ber_oid, |x: BerObject| x.as_oid().map(|o| o.clone()))
                >> s: parse_directory_string
                >> (Attr { oid: o, val: s })
        )
        .map(|(rem, x)| (rem, x.1))
    };
    fn parse_rdn(i: &[u8]) -> BerResult<Rdn> {
        parse_der_struct!(i, a: parse_attr_type_and_value >> (Rdn { a: a }))
            .map(|(rem, x)| (rem, x.1))
    }
    fn parse_name(i: &[u8]) -> BerResult<Name> {
        parse_der_struct!(i, l: many0!(complete!(parse_rdn)) >> (Name { l: l }))
            .map(|(rem, x)| (rem, x.1))
    }
    assert_eq!(parse_name(&bytes), Ok((empty, expected)));
}

#[test]
fn struct_with_garbage() {
    let bytes = [
        0x30, 0x0c, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x03, 0x01, 0x00, 0x00, 0xff, 0xff,
    ];
    let empty = &b""[..];
    let expected = (
        BerObjectHeader {
            class: 0,
            structured: 1,
            tag: BerTag::Sequence,
            len: 0xc,
        },
        MyStruct {
            a: BerObject::from_int_slice(b"\x01\x00\x01"),
            b: BerObject::from_int_slice(b"\x01\x00\x00"),
        },
    );
    assert_eq!(parse_struct01(&bytes), Ok((empty, expected)));
    assert_eq!(
        parse_struct01_complete(&bytes),
        Err(Err::Error(error_position!(&bytes[12..], ErrorKind::Eof)))
    );
}

#[test]
fn struct_verify_tag() {
    let bytes = [
        0x30, 0x0a, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x03, 0x01, 0x00, 0x00,
    ];
    let empty = &b""[..];
    let expected = (
        BerObjectHeader {
            class: 0,
            structured: 1,
            tag: BerTag::Sequence,
            len: 0xa,
        },
        MyStruct {
            a: BerObject::from_int_slice(b"\x01\x00\x01"),
            b: BerObject::from_int_slice(b"\x01\x00\x00"),
        },
    );
    let res = parse_struct04(&bytes, BerTag::Sequence);
    assert_eq!(res, Ok((empty, expected)));
    let res = parse_struct04(&bytes, BerTag::Set);
    assert_eq!(
        res,
        Err(Err::Error(error_position!(&bytes[..], ErrorKind::Verify)))
    );
}

#[test]
fn tagged_explicit() {
    fn parse_int_explicit(i: &[u8]) -> BerResult<u32> {
        map_res!(
            i,
            parse_der_tagged!(EXPLICIT 2, parse_ber_integer),
            |x: BerObject| x.as_u32()
        )
    }
    fn parse_int_noexplicit(i: &[u8]) -> BerResult<u32> {
        map_res!(
            i,
            parse_der_tagged!(2, parse_ber_integer),
            |x: BerObject| x.as_u32()
        )
    }
    let bytes = &[0xa2, 0x05, 0x02, 0x03, 0x01, 0x00, 0x01];
    // EXPLICIT tagged value parsing
    let res = parse_int_explicit(bytes);
    match res {
        Ok((rem, val)) => {
            assert!(rem.is_empty());
            assert_eq!(val, 0x10001);
        }
        _ => assert!(false),
    }
    // omitting EXPLICIT keyword
    let a = parse_int_explicit(bytes);
    let b = parse_int_noexplicit(bytes);
    assert_eq!(a, b);
    // wrong tag
    assert_eq!(
        parse_der_tagged!(bytes as &[u8], 3, parse_ber_integer),
        Err(Err::Error(error_position!(
            bytes as &[u8],
            ErrorKind::Verify
        )))
    );
    // wrong type
    assert_eq!(
        parse_der_tagged!(bytes as &[u8], 2, parse_ber_bool),
        Err(Err::Error(BerError::InvalidTag))
    );
}

#[test]
fn tagged_implicit() {
    fn parse_int_implicit(i: &[u8]) -> BerResult<u32> {
        map_res!(
            i,
            parse_der_tagged!(IMPLICIT 2, BerTag::Integer),
            |x: BerObject| x.as_u32()
        )
    }
    let bytes = &[0x82, 0x03, 0x01, 0x00, 0x01];
    // IMPLICIT tagged value parsing
    let res = parse_int_implicit(bytes);
    match res {
        Ok((rem, val)) => {
            assert!(rem.is_empty());
            assert_eq!(val, 0x10001);
        }
        _ => assert!(false),
    }
    // wrong tag
    assert_eq!(
        parse_der_tagged!(bytes as &[u8],IMPLICIT 3,BerTag::Integer),
        Err(Err::Error(error_position!(
            bytes as &[u8],
            ErrorKind::Verify
        )))
    );
}

#[test]
fn application() {
    #[derive(Debug, PartialEq)]
    struct SimpleStruct {
        a: u32,
    };
    fn parse_app01(i: &[u8]) -> BerResult<(BerObjectHeader, SimpleStruct)> {
        parse_der_application!(
            i,
            APPLICATION 2,
            a: map_res!(parse_ber_integer,|x: BerObject| x.as_u32()) >>
            ( SimpleStruct{ a } )
        )
    }
    let bytes = &[0x62, 0x05, 0x02, 0x03, 0x01, 0x00, 0x01];
    let res = parse_app01(bytes);
    match res {
        Ok((rem, (hdr, app))) => {
            assert!(rem.is_empty());
            assert_eq!(hdr.tag, BerTag::Integer);
            assert!(hdr.is_application());
            assert_eq!(hdr.structured, 1);
            assert_eq!(app, SimpleStruct { a: 0x10001 });
        }
        _ => assert!(false),
    }
}
