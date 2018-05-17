#[macro_use] extern crate pretty_assertions;

extern crate der_parser;

use der_parser::*;

#[test]
fn test_flat_take() {
    let empty = &b""[..];
    assert_eq!(parse_der_bool(&[0x01, 0x01, 0xff]), Ok((empty, DerObject::from_obj(DerObjectContent::Boolean(true)))));
    assert_eq!(parse_der_bool(&[0x01, 0x01, 0x00]), Ok((empty, DerObject::from_obj(DerObjectContent::Boolean(false)))));
    assert_eq!(der_read_element_content_as(&[0xff], 0x01, 0x01), Ok((empty, DerObjectContent::Boolean(true))));
    assert_eq!(der_read_element_content_as(&[0x00], 0x01, 0x01), Ok((empty, DerObjectContent::Boolean(false))));
}

