#![feature(test)]

extern crate test;
use test::Bencher;

extern crate der_parser;
#[macro_use]
extern crate nom;

use der_parser::{DerObject,DerObjectHeader,der_read_element_header,parse_der_integer,parse_der_u32};
use nom::IResult;


#[bench]
fn bench_der_read_element_header(b: &mut Bencher) {
    let bytes = &[ 0x0c, 0x0a,
                   0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65
    ];
    b.iter(|| {
        let res = der_read_element_header(bytes);
        match res {
            IResult::Done(_rem,hdr) => {
                assert_eq!(hdr, DerObjectHeader { class: 0, structured: 0, tag: 12, len: 10 });
            },
            _ => assert!(false),
        }
    });
}

#[bench]
fn bench_der_map_res_integer_u32(b: &mut Bencher) {
    let bytes : &[u8] = &[ 0x02, 0x04, 0x01, 0x23, 0x45, 0x67];
    b.iter(|| {
        let res = map_res!(bytes, parse_der_integer, |x:DerObject| x.as_u32());
        match res {
            IResult::Done(_rem,i) => {
                assert_eq!(i, 0x1234567);
            },
            _ => assert!(false),
        }
    });
}

#[bench]
fn bench_parse_der_u32(b: &mut Bencher) {
    let bytes : &[u8] = &[ 0x02, 0x04, 0x01, 0x23, 0x45, 0x67];
    b.iter(|| {
        let res = parse_der_u32(bytes);
        match res {
            IResult::Done(_rem,i) => {
                assert_eq!(i, 0x1234567);
            },
            _ => assert!(false),
        }
    });
}
