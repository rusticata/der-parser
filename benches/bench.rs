#![cfg(feature = "unstable")]
#![cfg(all(feature = "unstable", test))]
#![feature(test)]

extern crate test;
use test::Bencher;

use der_parser::ber::{Class, Header, Tag};
use der_parser::der::{
    der_read_element_header, parse_der, parse_der_integer, parse_der_u32, DerObject,
};
use der_parser::*;
use hex_literal::hex;
use nom::combinator::map_res;

#[bench]
fn bench_der_read_element_header(b: &mut Bencher) {
    let bytes = hex!("0c 0a 53 6f 6d 65 2d 53 74 61 74 65");
    b.iter(|| {
        let res = der_read_element_header(&bytes);
        match res {
            Ok((_rem, hdr)) => {
                assert_eq!(
                    hdr,
                    Header::new(Class::Universal, false, Tag(12), 10).with_raw_tag(Some(&[0xc]))
                );
            }
            _ => panic!("parsing failed"),
        }
    });
}

#[bench]
fn bench_der_map_res_integer_u32(b: &mut Bencher) {
    let bytes = hex!("02 04 01 23 45 67");
    b.iter(|| {
        let res = map_res(parse_der_integer, |x: DerObject| x.as_u32())(&bytes as &[u8]);
        match res {
            Ok((_rem, i)) => {
                assert_eq!(i, 0x0123_4567);
            }
            _ => panic!("parsing failed"),
        }
    });
}

#[bench]
fn bench_parse_der_u32(b: &mut Bencher) {
    let bytes = hex!("02 04 01 23 45 67");
    b.iter(|| {
        let res = parse_der_u32(&bytes);
        match res {
            Ok((_rem, i)) => {
                assert_eq!(i, 0x0123_4567);
            }
            _ => panic!("parsing failed"),
        }
    });
}

#[bench]
fn bench_parse_der_seq(b: &mut Bencher) {
    let bytes = hex!("30 0a 02 03 01 00 01 02 03 01 00 00");
    b.iter(|| {
        let res = parse_der(&bytes);
        let expected = DerObject::from_seq(vec![
            DerObject::from_int_slice(b"\x01\x00\x01"),
            DerObject::from_int_slice(b"\x01\x00\x00"),
        ]);
        match res {
            Ok((_rem, i)) => {
                assert_eq!(i, expected);
            }
            _ => panic!("parsing failed"),
        }
    });
}
