#[macro_use]
extern crate pretty_assertions;

#[macro_use]
extern crate hex_literal;
extern crate der_parser;
extern crate nom;

use der_parser::ber::*;
use der_parser::der::*;
use der_parser::error::*;
use der_parser::oid::Oid;
use nom::{Err, Needed};

#[test]
fn test_flat_take() {
    let empty = &b""[..];
    assert_eq!(
        parse_ber_bool(&[0x01, 0x01, 0xff]),
        Ok((empty, BerObject::from_obj(BerObjectContent::Boolean(true))))
    );
    assert_eq!(
        parse_ber_bool(&[0x01, 0x01, 0x00]),
        Ok((empty, BerObject::from_obj(BerObjectContent::Boolean(false))))
    );
    assert_eq!(
        ber_read_element_content_as(&[0xff], BerTag::Boolean, 0x01, false, 0),
        Ok((empty, BerObjectContent::Boolean(true)))
    );
    assert_eq!(
        ber_read_element_content_as(&[0x00], BerTag::Boolean, 0x01, false, 0),
        Ok((empty, BerObjectContent::Boolean(false)))
    );
}

#[test]
fn test_oid() {
    let empty = &b""[..];
    assert_eq!(
        parse_der(&[0x06, 0x06, 42, 129, 122, 1, 16, 9]),
        Ok((
            empty,
            BerObject::from_obj(BerObjectContent::OID(Oid::from(&[1, 2, 250, 1, 16, 9])))
        ))
    );
    // Dubuisson 433
    assert_eq!(
        parse_der(&[0x06, 0x05, 129, 122, 1, 16, 9]),
        Ok((
            empty,
            BerObject::from_obj(BerObjectContent::OID(Oid::from(&[250, 1, 16, 9])))
        ))
    );
}

#[test]
fn test_rel_oid() {
    let empty = &b""[..];
    assert_eq!(
        parse_der(&[0x0d, 0x04, 0xc2, 0x7b, 0x03, 0x02]),
        Ok((
            empty,
            BerObject::from_obj(BerObjectContent::RelativeOID(Oid::from(&[8571, 3, 2])))
        ))
    );
}

#[test]
fn test_unknown_tag() {
    let bytes = hex!("1d 01 00");
    let res = parse_ber(&bytes).expect("parsing failed");
    assert!(res.0.is_empty());
    assert_eq!(
        res.1,
        BerObject::from_obj(BerObjectContent::Unknown(BerTag(0x1d), &bytes[2..]))
    );
    let res = parse_der(&bytes).expect("parsing failed");
    assert!(res.0.is_empty());
    assert_eq!(
        res.1,
        BerObject::from_obj(BerObjectContent::Unknown(BerTag(0x1d), &bytes[2..]))
    );
}

#[test]
fn test_unknown_context_specific() {
    let bytes = hex!("80 01 00");
    let res = parse_ber(&bytes).expect("parsing failed");
    assert!(res.0.is_empty());
    assert_eq!(
        res.1,
        BerObject {
            class: 2,
            structured: 0,
            tag: BerTag(0),
            content: BerObjectContent::Unknown(BerTag(0x0), &bytes[2..])
        }
    );
}

#[test]
fn test_unknown_long_tag() {
    let bytes = hex!("9f 22 01 00");
    let res = parse_ber(&bytes).expect("parsing failed");
    assert!(res.0.is_empty());
    assert_eq!(
        res.1,
        BerObject {
            class: 2,
            structured: 0,
            tag: BerTag(0x22),
            content: BerObjectContent::Unknown(BerTag(0x22), &bytes[3..])
        }
    );
}

#[test]
fn test_unknown_longer_tag() {
    let bytes = hex!("9f a2 22 01 00");
    let res = parse_ber(&bytes).expect("parsing failed");
    assert!(res.0.is_empty());
    assert_eq!(
        res.1,
        BerObject {
            class: 2,
            structured: 0,
            tag: BerTag(0x1122),
            content: BerObjectContent::Unknown(BerTag(0x1122), &bytes[4..])
        }
    );
}

#[test]
fn test_incomplete_tag() {
    let bytes = hex!("9f a2 a2");
    let res = parse_ber(&bytes);
    assert!(res.is_err());
}

#[test]
fn test_overflow_tag() {
    let bytes = hex!("9f a2 a2 a2 a2 a2 22 01 00");
    let res = parse_ber(&bytes);
    assert!(res.is_err());
}

#[test]
fn test_incomplete_length() {
    let bytes = hex!("30");
    let res = parse_ber(&bytes).err().expect("expected error");
    assert_eq!(res, Err::Incomplete(Needed::Size(1)));
    let res = parse_der(&bytes).err().expect("expected error");
    assert_eq!(res, Err::Incomplete(Needed::Size(1)));
    let bytes = hex!("02");
    let res = parse_ber(&bytes).err().expect("expected error");
    assert_eq!(res, Err::Incomplete(Needed::Size(1)));
    let bytes = hex!("02 05");
    let _ = parse_ber(&bytes).err().expect("expected error");
    let bytes = hex!("02 85");
    let res = parse_ber(&bytes).err().expect("expected error");
    assert_eq!(res, Err::Incomplete(Needed::Size(5)));
    let bytes = hex!("02 85 ff");
    let res = parse_ber(&bytes).err().expect("expected error");
    assert_eq!(res, Err::Incomplete(Needed::Size(5)));
}

#[test]
fn test_invalid_length() {
    let bytes = hex!("02 ff 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10");
    let _ = parse_ber(&bytes).err().expect("expected error");
    let _ = ber_read_element_header(&bytes)
        .err()
        .expect("expected error");
    let bytes = hex!("02 85 ff ff ff ff ff 00");
    let res = parse_ber(&bytes)
        .err()
        .expect("parsing should have returned error");
    // get error
    match res {
        Err::Error(e) => {
            assert_eq!(e, BerError::InvalidLength);
        }
        _ => assert!(false),
    }
    let bytes = hex!("02 02 00");
    let res = parse_der(&bytes).err().expect("expected error");
    assert_eq!(res, Err::Incomplete(Needed::Size(2)));
}

#[test]
fn test_invalid_param() {
    let bytes = hex!("00");
    let hdr = BerObjectHeader {
        class: 8,
        structured: 0,
        tag: BerTag(2),
        len: 1,
    };
    der_read_element_content(&bytes, hdr)
        .err()
        .expect("expected erreur");
}

#[test]
fn test_pretty_print() {
    let bytes = hex!("01 01 ff");
    let obj = parse_der(&bytes).map(|(_, b)| b).expect("expected error");
    println!("{:?}", obj.as_pretty(0, 2));

    // controlling the pretty-printer
    let mut pp = obj.as_pretty(0, 4);
    pp.set_flag(PrettyPrinterFlag::ShowHeader);
    println!("{:?}", pp);
}
