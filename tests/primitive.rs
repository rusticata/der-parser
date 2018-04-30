#[macro_use] extern crate pretty_assertions;

extern crate der_parser;

extern crate nom;

use der_parser::*;
use nom::IResult;

#[test]
fn test_flat_take() {
    let empty = &b""[..];
    assert_eq!(parse_der_bool(&[0x01, 0x01, 0xff]), IResult::Done(empty, DerObject::from_obj(DerObjectContent::Boolean(true))));
    assert_eq!(parse_der_bool(&[0x01, 0x01, 0x00]), IResult::Done(empty, DerObject::from_obj(DerObjectContent::Boolean(false))));
    assert_eq!(der_read_element_content_as(&[0xff], 0x01, 0x01), IResult::Done(empty, DerObjectContent::Boolean(true)));
    assert_eq!(der_read_element_content_as(&[0x00], 0x01, 0x01), IResult::Done(empty, DerObjectContent::Boolean(false)));
}

