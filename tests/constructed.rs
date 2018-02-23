#[macro_use]
extern crate der_parser;

#[macro_use]
extern crate nom;

use der_parser::*;
use oid::Oid;
use nom::{IResult,ErrorKind};

#[derive(Debug, PartialEq)]
struct MyStruct<'a>{
    a: DerObject<'a>,
    b: DerObject<'a>,
}

fn parse_struct01(i: &[u8]) -> IResult<&[u8],(DerObjectHeader,MyStruct)> {
    parse_der_struct!(
        i,
        a: parse_der_integer >>
        b: parse_der_integer >>
        ( MyStruct{ a: a, b: b } )
    )
}

fn parse_struct01_complete(i: &[u8]) -> IResult<&[u8],(DerObjectHeader,MyStruct)> {
    parse_der_struct!(
        i,
        a: parse_der_integer >>
        b: parse_der_integer >>
           eof!() >>
        ( MyStruct{ a: a, b: b } )
    )
}

// calling user function
#[allow(dead_code)]
fn parse_struct02(i: &[u8]) -> IResult<&[u8],(DerObjectHeader,())> {
    parse_der_struct!(
        i,
        _a: parse_der_integer >>
        _b: parse_struct01 >>
        ( () )
    )
}

// embedded DER structs
#[allow(dead_code)]
fn parse_struct03(i: &[u8]) -> IResult<&[u8],(DerObjectHeader,())> {
    parse_der_struct!(
        i,
        _a: parse_der_integer >>
        _b: parse_der_struct!(
                parse_der_integer >>
                ( () )
            ) >>
        ( () )
    )
}

#[test]
fn struct01() {
    let bytes = [ 0x30, 0x0a,
                  0x02, 0x03, 0x01, 0x00, 0x01,
                  0x02, 0x03, 0x01, 0x00, 0x00,
    ];
    let empty = &b""[..];
    let expected = (
        DerObjectHeader{
            class: 0,
            structured: 1,
            tag: 0x10,
            len: 0xa,
        },
        MyStruct {
            a: DerObject::from_int_slice(b"\x01\x00\x01"),
            b: DerObject::from_int_slice(b"\x01\x00\x00"),
        }
    );
    let res = parse_struct01(&bytes);
    assert_eq!(res, IResult::Done(empty, expected));
}

#[test]
fn struct02() {
    let empty = &b""[..];
    let bytes = [
        0x30, 0x45, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
        0x02, 0x46, 0x52, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08,
        0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65,
        0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49,
        0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67,
        0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64
    ];
    #[derive(Debug, PartialEq)]
    struct Attr<'a> {
        oid: Oid,
        val: DerObject<'a>,
    };
    #[derive(Debug, PartialEq)]
    struct Rdn<'a> {
        a: Attr<'a>
    }
    #[derive(Debug, PartialEq)]
    struct Name<'a> {
        l: Vec<Rdn<'a>>
    }
    let expected = Name {
        l: vec![
            Rdn{
                a: Attr{
                    oid: Oid::from(&[2, 5, 4, 6]), // countryName
                    val: DerObject::from_obj(DerObjectContent::PrintableString(b"FR")),
                }
            },
            Rdn{
                a: Attr{
                    oid: Oid::from(&[2, 5, 4, 8]), // stateOrProvinceName
                    val: DerObject::from_obj(DerObjectContent::UTF8String(b"Some-State")),
                }
            },
            Rdn{
                a: Attr{
                    oid: Oid::from(&[2, 5, 4, 10]), // organizationName
                    val: DerObject::from_obj(DerObjectContent::UTF8String(b"Internet Widgits Pty Ltd")),
                }
            },
        ]
    };
    fn parse_directory_string(i:&[u8]) -> IResult<&[u8],DerObject> {
        alt!(i, parse_der_utf8string | parse_der_printablestring | parse_der_ia5string)
    }
    fn parse_attr_type_and_value(i:&[u8]) -> IResult<&[u8],Attr> {
        parse_der_struct!(i,
            o: map_res!(parse_der_oid,|x: DerObject| x.as_oid().map(|o| o.clone())) >>
            s: parse_directory_string >>
            ( Attr{oid: o, val: s} )
        ).map(|x| x.1)
    };
    fn parse_rdn(i:&[u8]) -> IResult<&[u8],Rdn> {
        parse_der_struct!(i,
            a: parse_attr_type_and_value >>
            ( Rdn{a: a} )
        ).map(|x| x.1)
    }
    fn parse_name(i:&[u8]) -> IResult<&[u8],Name> {
        parse_der_struct!(i,
            l: many0!(parse_rdn) >>
            ( Name{l: l} )
        ).map(|x| x.1)
    }
    assert_eq!(parse_name(&bytes), IResult::Done(empty, expected));
}

#[test]
fn struct_with_garbage() {
    let bytes = [ 0x30, 0x0c,
                  0x02, 0x03, 0x01, 0x00, 0x01,
                  0x02, 0x03, 0x01, 0x00, 0x00,
                  0xff, 0xff
    ];
    let empty = &b""[..];
    let expected = (
        DerObjectHeader{
            class: 0,
            structured: 1,
            tag: 0x10,
            len: 0xc,
        },
        MyStruct {
            a: DerObject::from_int_slice(b"\x01\x00\x01"),
            b: DerObject::from_int_slice(b"\x01\x00\x00"),
        }
    );
    assert_eq!(parse_struct01(&bytes), IResult::Done(empty, expected));
    assert_eq!(parse_struct01_complete(&bytes), IResult::Error(error_position!(ErrorKind::Eof,&bytes[2..])));
}


