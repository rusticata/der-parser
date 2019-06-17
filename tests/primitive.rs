#[macro_use] extern crate pretty_assertions;

extern crate der_parser;

use der_parser::*;
use der_parser::ber::*;
use der_parser::oid::Oid;

#[test]
fn test_flat_take() {
    let empty = &b""[..];
    assert_eq!(parse_ber_bool(&[0x01, 0x01, 0xff]), Ok((empty, BerObject::from_obj(BerObjectContent::Boolean(true)))));
    assert_eq!(parse_ber_bool(&[0x01, 0x01, 0x00]), Ok((empty, BerObject::from_obj(BerObjectContent::Boolean(false)))));
    assert_eq!(ber_read_element_content_as(&[0xff], BerTag::Boolean, 0x01, false, 0), Ok((empty, BerObjectContent::Boolean(true))));
    assert_eq!(ber_read_element_content_as(&[0x00], BerTag::Boolean, 0x01, false, 0), Ok((empty, BerObjectContent::Boolean(false))));
}

#[test]
fn test_oid() {
    let empty = &b""[..];
    assert_eq!(parse_der(&[0x06, 0x06, 42, 129, 122, 1, 16, 9]), Ok((empty, BerObject::from_obj(BerObjectContent::OID(Oid::from(&[1,2,250,1,16,9]))))));
    // Dubuisson 433
    assert_eq!(parse_der(&[0x06, 0x05, 129, 122, 1, 16, 9]), Ok((empty, BerObject::from_obj(BerObjectContent::OID(Oid::from(&[250,1,16,9]))))));
}

#[test]
fn test_rel_oid() {
    let empty = &b""[..];
    assert_eq!(parse_der(&[0x0d, 0x04, 0xc2, 0x7b, 0x03, 0x02]), Ok((empty, BerObject::from_obj(BerObjectContent::RelativeOID(Oid::from(&[8571,3,2]))))));
}
