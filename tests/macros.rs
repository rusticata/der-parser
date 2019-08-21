#[macro_use]
extern crate der_parser;

use der_parser::ber::{parse_ber_integer, BerObject, BerObjectHeader};
use der_parser::der::{parse_der_enum, parse_der_integer};
use der_parser::error::{BerResult, DerResult};

// Do not import nom, to check types and re-exports

// all following functions are declared to check if macros from
// der-parser can be used without importing nom or rusticata_macros

#[derive(Debug, PartialEq)]
struct MyStruct<'a> {
    a: BerObject<'a>,
    b: BerObject<'a>,
}

#[allow(dead_code)]
fn parse_seq_m(i: &[u8]) -> DerResult {
    parse_der_sequence_defined_m! {
        i,
        parse_der_integer >>
        parse_der_integer
    }
}

#[allow(dead_code)]
fn parse_set_m(i: &[u8]) -> DerResult {
    parse_der_set_defined_m! {
        i,
        parse_der_integer >>
        parse_der_integer
    }
}

#[allow(dead_code)]
fn parse_seq(i: &[u8]) -> DerResult {
    parse_der_sequence_defined! {
        i,
        parse_der_integer >>
        parse_der_integer
    }
}

#[allow(dead_code)]
fn parse_set(i: &[u8]) -> DerResult {
    parse_der_set_defined! {
        i,
        parse_der_integer >>
        parse_der_integer
    }
}

#[allow(dead_code)]
fn parse_seq_of_int(i: &[u8]) -> DerResult {
    parse_der_sequence_of!(i, parse_der_integer)
}

#[allow(dead_code)]
fn parse_set_of_int(i: &[u8]) -> DerResult {
    parse_der_set_of!(i, parse_der_integer)
}

#[allow(dead_code)]
fn parse_optional_enum(i: &[u8]) -> DerResult {
    parse_der_optional!(i, parse_der_enum)
}

#[allow(dead_code)]
fn parse_struct01(i: &[u8]) -> BerResult<(BerObjectHeader, MyStruct)> {
    parse_der_struct!(
        i,
        a: parse_ber_integer >> b: parse_ber_integer >> (MyStruct { a: a, b: b })
    )
}

#[allow(dead_code)]
fn parse_tagged_int(i: &[u8]) -> BerResult {
    parse_der_tagged!(i, EXPLICIT 2, parse_ber_integer)
}

#[derive(Debug, PartialEq)]
struct SimpleStruct {
    a: u32,
}

#[allow(dead_code)]
fn parse_app_int(i: &[u8]) -> BerResult<(BerObjectHeader, SimpleStruct)> {
    parse_der_application!(
        i,
        APPLICATION 2,
        a: map_res!(parse_ber_integer,|x: BerObject| x.as_u32()) >>
        ( SimpleStruct{ a } )
    )
}

#[test]
fn macros() {}
