#[macro_use]
extern crate pretty_assertions;

#[macro_use]
extern crate hex_literal;
extern crate der_parser;
extern crate nom;

use der_parser::ber::*;
use der_parser::error::*;
use der_parser::oid::*;
use nom::Err;

#[test]
fn test_ber_bool() {
    let empty = &b""[..];
    let b_true = BerObject::from_obj(BerObjectContent::Boolean(true));
    let b_false = BerObject::from_obj(BerObjectContent::Boolean(false));
    assert_eq!(parse_ber_bool(&[0x01, 0x01, 0x00]), Ok((empty, b_false)));
    assert_eq!(
        parse_ber_bool(&[0x01, 0x01, 0xff]),
        Ok((empty, b_true.clone()))
    );
    assert_eq!(parse_ber_bool(&[0x01, 0x01, 0x7f]), Ok((empty, b_true)));
    assert_eq!(
        parse_ber_bool(&[0x01, 0x02, 0x12, 0x34]),
        Err(Err::Error(BerError::InvalidLength))
    );
}

#[test]
fn test_seq_indefinite_length() {
    let data = hex!("30 80 04 03 56 78 90 00 00 02 01 01");
    let res = parse_ber(&data);
    assert_eq!(
        res,
        Ok((
            &data[9..],
            BerObject::from_seq(vec![BerObject::from_obj(BerObjectContent::OctetString(
                &data[4..=6]
            )),])
        ))
    );
    let res = parse_ber_sequence(&data);
    assert_eq!(
        res,
        Ok((
            &data[9..],
            BerObject::from_seq(vec![BerObject::from_obj(BerObjectContent::OctetString(
                &data[4..=6]
            )),])
        ))
    );
}

#[test]
fn test_set_indefinite_length() {
    let data = hex!("31 80 04 03 56 78 90 00 00");
    let res = parse_ber(&data);
    assert_eq!(
        res,
        Ok((
            &data[9..],
            BerObject::from_set(vec![BerObject::from_obj(BerObjectContent::OctetString(
                &data[4..=6]
            )),])
        ))
    );
    let res = parse_ber_set(&data);
    assert_eq!(
        res,
        Ok((
            &data[9..],
            BerObject::from_set(vec![BerObject::from_obj(BerObjectContent::OctetString(
                &data[4..=6]
            )),])
        ))
    );
}

#[test]
fn test_ber_int() {
    let empty = &b""[..];
    let bytes = [0x02, 0x03, 0x01, 0x00, 0x01];
    let expected = BerObject::from_obj(BerObjectContent::Integer(b"\x01\x00\x01"));
    assert_eq!(parse_ber_integer(&bytes), Ok((empty, expected)));
}

#[test]
fn test_ber_bitstring_primitive() {
    let empty = &b""[..];
    let bytes = &[0x03, 0x07, 0x04, 0x0a, 0x3b, 0x5f, 0x29, 0x1c, 0xd0];
    let expected = BerObject::from_obj(BerObjectContent::BitString(
        4,
        BitStringObject { data: &bytes[3..] },
    ));
    assert_eq!(parse_ber_bitstring(bytes), Ok((empty, expected)));
    //
    // correct encoding, padding bits not all set to 0
    //
    let bytes = &[0x03, 0x04, 0x06, 0x6e, 0x5d, 0xe0];
    let expected = BerObject::from_obj(BerObjectContent::BitString(
        6,
        BitStringObject { data: &bytes[3..] },
    ));
    assert_eq!(parse_ber_bitstring(bytes), Ok((empty, expected)));
    //
    // long form of length
    //
    let bytes = &[0x03, 0x81, 0x04, 0x06, 0x6e, 0x5d, 0xc0];
    let expected = BerObject::from_obj(BerObjectContent::BitString(
        6,
        BitStringObject { data: &bytes[4..] },
    ));
    assert_eq!(parse_ber_bitstring(bytes), Ok((empty, expected)));
}

#[test]
fn test_ber_bitstring_constructed() {
    let bytes = &[
        0x23, 0x80, 0x03, 0x03, 0x00, 0x0a, 0x3b, 0x03, 0x05, 0x04, 0x5f, 0x29, 0x1c, 0xd0, 0x00,
        0x00,
    ];
    assert_eq!(
        parse_ber_bitstring(bytes),
        Err(Err::Error(BerError::Unsupported))
    ); // XXX valid encoding
}

#[test]
fn test_ber_octetstring_primitive() {
    let empty = &b""[..];
    let bytes = [0x04, 0x05, 0x41, 0x41, 0x41, 0x41, 0x41];
    let expected = BerObject::from_obj(BerObjectContent::OctetString(b"AAAAA"));
    assert_eq!(parse_ber_octetstring(&bytes), Ok((empty, expected)));
}

#[test]
fn test_ber_null() {
    let empty = &b""[..];
    let expected = BerObject::from_obj(BerObjectContent::Null);
    assert_eq!(parse_ber_null(&[0x05, 0x00]), Ok((empty, expected)));
}

#[test]
fn test_ber_oid() {
    let empty = &b""[..];
    let bytes = [
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05,
    ];
    let expected = BerObject::from_obj(BerObjectContent::OID(Oid::from(&[
        1, 2, 840, 113549, 1, 1, 5,
    ])));
    assert_eq!(parse_ber_oid(&bytes), Ok((empty, expected)));
}

#[test]
fn test_ber_enum() {
    let empty = &b""[..];
    let expected = BerObject::from_obj(BerObjectContent::Enum(2));
    assert_eq!(parse_ber_enum(&[0x0a, 0x01, 0x02]), Ok((empty, expected)));
}

#[test]
fn test_ber_utf8string() {
    let empty = &b""[..];
    let bytes = [
        0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65,
    ];
    let expected = BerObject::from_obj(BerObjectContent::UTF8String(b"Some-State"));
    assert_eq!(parse_ber_utf8string(&bytes), Ok((empty, expected)));
}

#[test]
fn test_ber_relativeoid() {
    let empty = &b""[..];
    let bytes = hex!("0d 04 c2 7b 03 02");
    let expected = BerObject::from_obj(BerObjectContent::RelativeOID(Oid::from(&[8571, 3, 2])));
    assert_eq!(parse_ber_relative_oid(&bytes), Ok((empty, expected)));
}

#[test]
fn test_ber_bmpstring() {
    let empty = &b""[..];
    let bytes = hex!("1e 08 00 55 00 73 00 65 00 72");
    let expected = BerObject::from_obj(BerObjectContent::BmpString(b"\x00U\x00s\x00e\x00r"));
    assert_eq!(parse_ber_bmpstring(&bytes), Ok((empty, expected)));
}
