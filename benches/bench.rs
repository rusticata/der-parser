#![feature(test)]

extern crate test;
use test::Bencher;

extern crate der_parser;
extern crate nom;

use der_parser::{der_read_element_header,DerObjectHeader};
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
