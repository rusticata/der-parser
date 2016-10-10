use std::vec::Vec;
use std::ops::Index;
//use nom::{IResult, space, alpha, alphanumeric, digit};
use nom::{be_u8,IResult,Err,ErrorKind};

//use common::{Tag};
use common::bytes_to_u64;

#[derive(Clone,Copy,Debug,PartialEq)]
pub struct DerElement {
    class: u8,
    structured: u8,
    tag: u8,
}

#[derive(Clone,Copy,Debug,PartialEq)]
pub struct DerElementHeader {
    elt: DerElement,
    len: u64,
}


named!(parse_identifier<(&[u8],usize),DerElement>,
  chain!(
    class: take_bits!(u8, 2) ~
    structured: take_bits!(u8, 1) ~
    tag: take_bits!(u8, 5) ,
    || { DerElement{class:class,structured:structured,tag:tag} }
  )
);

#[derive(Debug,Clone,PartialEq)]
pub enum DerObject<'a> {
    Boolean(bool),
    Integer(u64),
    BitString(u8, &'a [u8]),
    OctetString(&'a [u8]),
    Null,
    Enum(u64),
    OID(Vec<u64>),
    NumericString(&'a[u8]),
    PrintableString(&'a[u8]),
    IA5String(&'a[u8]),
    UTF8String(&'a[u8]),

    Sequence(Vec<DerObject<'a> >),
    Set(Vec<DerObject<'a> >),

    UTCTime(&'a [u8]),

    ContextSpecific(/*tag:*/u8,&'a[u8]),
    Unknown(DerElementHeader, &'a[u8]),
}

impl<'a> DerObject<'a> {
    pub fn as_u32(&self) -> Option<u32> {
        match self {
            &DerObject::Integer(i) => Some(i as u32),
            _ => None,
        }
    }
}

// This is a consuming iterator
impl<'a> IntoIterator for DerObject<'a> {
    type Item = DerObject<'a>;
    type IntoIter = DerObjectIntoIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        // match self {
        //     DerObject::Sequence(ref v) => (),
        //     _ => (),
        // };
        DerObjectIntoIterator{ val: self, idx: 0 }
    }
}

pub struct DerObjectIntoIterator<'a> {
    val: DerObject<'a>,
    idx: usize,
}

impl<'a> Iterator for DerObjectIntoIterator<'a> {
    type Item = DerObject<'a>;
    fn next(&mut self) -> Option<DerObject<'a>> {
        // let result = if self.idx < self.vec.len() {
        //     Some(self.vec[self.idx].clone())
        // } else {
        //     None
        // };
        let res =
            match self.val {
                DerObject::Sequence(ref v) if self.idx < v.len() => Some(v[self.idx].clone()),
                DerObject::Set(ref v) if self.idx < v.len() => Some(v[self.idx].clone()),
                _ => if self.idx == 0 { Some(self.val.clone()) } else { None },
            };
        self.idx += 1;
        res
    }
}

// impl<'a> Iterator for DerObject<'a> {
//     type Item = DerObject<'a>;
// 
//     fn next(&mut self) -> Option<DerObject<'a>> {
//         None
//     }
// }

pub struct DerObjectRefIterator<'a> {
    obj: &'a DerObject<'a>,
    idx: usize,
}

impl<'a> Iterator for DerObjectRefIterator<'a> {
    type Item = &'a DerObject<'a>;
    fn next(&mut self) -> Option<&'a DerObject<'a>> {
        let res = match *self.obj {
                DerObject::Sequence(ref v) if self.idx < v.len() => Some(&v[self.idx]),
                DerObject::Set(ref v) if self.idx < v.len() => Some(&v[self.idx]),
                _ => None,
            };
        self.idx += 1;
        res
    }
}

impl<'a> DerObject<'a> {
    pub fn ref_iter(&'a self) -> DerObjectRefIterator<'a> {
        DerObjectRefIterator{ obj:&self, idx:0 }
    }
}

impl<'a> Index<usize> for DerObject<'a> {
    type Output = DerObject<'a>;

    fn index(&self, idx: usize) -> &DerObject<'a> {
        match *self {
            DerObject::Sequence(ref v) if idx < v.len() => &v[idx],
            DerObject::Set(ref v) if idx < v.len() => &v[idx],
            _ => panic!("Try to index DerObject which is not structured"),
        }
        // XXX the following
        // self.ref_iter().nth(idx).unwrap()
        // fails with:
        // error: cannot infer an appropriate lifetime for autoref due to conflicting requirements [E0495]
        // self.ref_iter().nth(idx).unwrap()
    }
}



named!(parse_der_length_byte<(&[u8],usize),(u8,u8)>,
  chain!(
    msb: take_bits!(u8, 1) ~
    low7: take_bits!(u8, 7),
    || { debug!("(msb,low7)=({},{})",msb,low7); (msb,low7) }
  )
);


fn der_read_oid<'a>(i: &'a[u8]) -> Vec<u64> {
    let mut oid = Vec::new();
    let mut acc : u64;

    /* first element = X*40 + Y (See 8.19.4) */
    acc = i[0] as u64;
    oid.push( acc / 40);
    oid.push( acc % 40);

    acc = 0;
    for &c in &i[1..] {
        acc = (acc << 7) | (c & 0b01111111) as u64;
        if (c & (1<<7)) == 0 {
            oid.push(acc);
            acc = 0;
        }
    }
    assert!(acc == 0);

    oid
}


named!(der_read_element_header<&[u8],DerElementHeader>,
    chain!(
        el: bits!(
            parse_identifier
        ) ~
        len: bits!(
            parse_der_length_byte
        ) ~
        llen: cond!(len.0 == 1, take!(len.1)),

        || {
            debug!("hdr: {:?}",el);
            let len : u64 = match len.0 {
                0 => len.1 as u64,
                _ => bytes_to_u64(llen.unwrap()).unwrap(),
            };
            DerElementHeader {
                elt: el,
                len: len,
            }
        }
    )
);

named!(der_read_sequence_contents<&[u8],Vec<DerObject> >,
    many0!(parse_der)
);

fn der_read_element_contents<'a,'b>(i: &'a[u8], hdr: DerElementHeader) -> IResult<&'a [u8], DerObject<'a>> {
    debug!("der_read_element_contents: {:?}", hdr);
    debug!("i len: {}", i.len());
    match hdr.elt.class {
        // universal
        0b00 => (),
        // application
        0b01 => (),
        // context-specific
        0b10 => return chain!(i,b: take!(hdr.len),|| { DerObject::ContextSpecific(hdr.elt.tag,b) }),
        // private
        0b11 => (),
        _    => { return IResult::Error(Err::Code(ErrorKind::Custom(128))); },
    }
    match hdr.elt.tag {
        // 0x00 end-of-content
        // 0x01 bool
        0x01 => {
                    chain!(i,
                        b: switch!(take!(1),
                          b"\x00" => value!(true) |
                          b"\xff" => value!(false)
                        ),
                        || {
                        DerObject::Boolean(b) }
                    )
                },
        // 0x02: integer
        0x02 => {
                    chain!(i,
                        i: parse_hex_to_u64!(hdr.len),
                        || { DerObject::Integer(i) }
                    )
                },
        // 0x03: bitstring
        0x03 => {
                    chain!(i,
                        ignored_bits: be_u8 ~
                        s: take!(hdr.len - 1), // XXX we must check if constructed or not (8.7)
                        || { DerObject::BitString(ignored_bits,s) }
                    )
                },
        // 0x04: octetstring
        0x04 => {
                    chain!(i,
                        s: take!(hdr.len), // XXX we must check if constructed or not (8.7)
                        || { DerObject::OctetString(s) }
                    )
                },
        // 0x05: null
        0x05 => { IResult::Done(i,DerObject::Null) },
        // 0x06: object identified
        0x06 => {
                    chain!(i,
                        i: map!(take!(hdr.len),der_read_oid),
                        || { assert!(hdr.elt.structured == 0); DerObject::OID(i) }
                    )
                },
        // 0x0a: enumerated
        0x0a => {
                    chain!(i,
                        i: parse_hex_to_u64!(hdr.len),
                        || { DerObject::Enum(i) }
                    )
                },
        // 0x0c: UTF8String
        0x0c => {
                    chain!(i,
                        s: take!(hdr.len), // XXX we must check if constructed or not (8.7)
                        || { DerObject::UTF8String(s) }
                    )
                },
        // 0x10: sequence
        0x10 => {
                    chain!(i,
                        l: flat_map!(take!(hdr.len),der_read_sequence_contents),
                        || { DerObject::Sequence(l) }
                    )
                },
        // 0x11: set
        0x11 => {
                    chain!(i,
                        l: flat_map!(take!(hdr.len),der_read_sequence_contents),
                        || { DerObject::Set(l) }
                    )
                },
        // 0x12: numericstring
        0x12 => {
                    chain!(i,
                        s: take!(hdr.len), // XXX we must check if constructed or not (8.7)
                        || { DerObject::NumericString(s) }
                    )
                },
        // 0x13: printablestring
        0x13 => {
                    chain!(i,
                        s: take!(hdr.len), // XXX we must check if constructed or not (8.7)
                        || { DerObject::PrintableString(s) }
                    )
                },

        // 0x16: ia5string
        0x16 => {
                    chain!(i,
                        s: take!(hdr.len), // XXX we must check if constructed or not (8.7)
                        || { DerObject::IA5String(s) }
                    )
                },
        // 0x17: utctime
        0x17 => {
                    chain!(i,
                        s: take!(hdr.len), // XXX we must check if constructed or not (8.7)
                        || { DerObject::UTCTime(s) }
                    )
                },
        // all unknown values
        _    => {
                    chain!(i,
                        b: take!(hdr.len),
                        || { DerObject::Unknown(hdr, b) }
                    )
                },
    }
}

named!(pub parse_der_integer<DerObject>,
   chain!(
       hdr: der_read_element_header ~
       error_if!(hdr.elt.class != 0b00, Err::Code(ErrorKind::Custom(128))) ~
       error_if!(hdr.elt.tag != 0x02, Err::Code(ErrorKind::Custom(128))) ~
       contents: apply!(der_read_element_contents,hdr),
       || { contents }
   )
);

named!(pub parse_der_sequence<DerObject>,
   chain!(
       hdr: der_read_element_header ~
       error_if!(hdr.elt.class != 0b00, Err::Code(ErrorKind::Custom(128))) ~
       error_if!(hdr.elt.structured != 0b1, Err::Code(ErrorKind::Custom(128))) ~
       error_if!(hdr.elt.tag != 0x10, Err::Code(ErrorKind::Custom(128))) ~
       contents: apply!(der_read_element_contents,hdr),
       || { contents }
   )
);

named!(pub parse_der<&[u8],DerObject>,
    chain!(
        hdr: der_read_element_header ~
        contents: apply!(der_read_element_contents,hdr),

        || {
            debug!("el: {:?}",hdr.elt);
            debug!("contents: {:?}",contents);
            contents
        }
    )
);

#[cfg(test)]
mod tests {
    //use super::*;
    use der::{parse_der,DerObject};
    use nom::IResult;

    use nom::Err::*;
    use nom::ErrorKind;

    extern crate env_logger;

#[test]
fn test_der_bool() {
    let empty = &b""[..];
    assert_eq!(parse_der(&[0x01, 0x01, 0x00]), IResult::Done(empty, DerObject::Boolean(true)));
    assert_eq!(parse_der(&[0x01, 0x01, 0xff]), IResult::Done(empty, DerObject::Boolean(false)));
    let bytes = [0x01, 0x01, 0x7f];
    assert_eq!(parse_der(&bytes[..]), IResult::Error(Position(ErrorKind::Switch, &bytes[2..])));
}

#[test]
fn test_der_int() {
    let empty = &b""[..];
    let bytes = [0x02, 0x03, 0x01, 0x00, 0x01];
    let expected = DerObject::Integer(65537);
    assert_eq!(parse_der(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_octetstring() {
    let empty = &b""[..];
    let bytes = [ 0x04, 0x05,
                  0x41, 0x41, 0x41, 0x41, 0x41,
    ];
    let expected = DerObject::OctetString(b"AAAAA");
    assert_eq!(parse_der(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_null() {
    let empty = &b""[..];
    assert_eq!(parse_der(&[0x05, 0x00]), IResult::Done(empty, DerObject::Null));
}

#[test]
fn test_der_enum() {
    let empty = &b""[..];
    assert_eq!(parse_der(&[0x0a, 0x01, 0x02]), IResult::Done(empty, DerObject::Enum(2)));
}

#[test]
fn test_der_oid() {
    let empty = &b""[..];
    let bytes = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05];
    assert_eq!(parse_der(&bytes), IResult::Done(empty, DerObject::OID(vec![1, 2, 840, 113549, 1, 1, 5])));
}

#[test]
fn test_der_utctime() {
    let empty = &b""[..];
    let bytes = [0x17, 0x0D, 0x30, 0x32, 0x31, 0x32, 0x31, 0x33, 0x31, 0x34, 0x32, 0x39, 0x32, 0x33, 0x5A ];
    assert_eq!(parse_der(&bytes), IResult::Done(empty, DerObject::UTCTime(&bytes[2..])));
}

#[test]
fn test_der_utf8string() {
    let empty = &b""[..];
    let bytes = [ 0x0c, 0x0a,
                  0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65
    ];
    let expected = DerObject::UTF8String(b"Some-State");
    assert_eq!(parse_der(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_seq() {
    let empty = &b""[..];
    let bytes = [ 0x30, 0x05,
                  0x02, 0x03, 0x01, 0x00, 0x01,
    ];
    let expected = DerObject::Sequence(
        vec![DerObject::Integer(65537)]
    );
    assert_eq!(parse_der(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_set() {
    let empty = &b""[..];
    let bytes = [
        0x31, 0x05,
        0x02, 0x03, 0x01, 0x00, 0x01, // Integer 65537
    ];
    let expected = DerObject::Set(
        vec![DerObject::Integer(65537)]
    );
    assert_eq!(parse_der(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_contextspecific() {
    let empty = &b""[..];
    let data = [0x02, 0x01, 0x02];
    let expected = DerObject::ContextSpecific(0,&data);
    assert_eq!(parse_der(&[0xa0, 0x03, 0x02, 0x01, 0x02]), IResult::Done(empty, expected));
}

#[test]
fn test_der_seq_dn() {
    let empty = &b""[..];
    let bytes = [
        0x30, 0x45, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
        0x02, 0x46, 0x52, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08,
        0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65,
        0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49,
        0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67,
        0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64
    ];
    let expected = DerObject::Sequence(
        vec![
            DerObject::Set(vec![
                DerObject::Sequence(vec![
                    DerObject::OID(vec![2, 5, 4, 6]), // countryName
                    DerObject::PrintableString(b"FR"),
                ]),
            ]),
            DerObject::Set(vec![
                DerObject::Sequence(vec![
                    DerObject::OID(vec![2, 5, 4, 8]), // stateOrProvinceName
                    DerObject::UTF8String(b"Some-State"),
                ]),
            ]),
            DerObject::Set(vec![
                DerObject::Sequence(vec![
                    DerObject::OID(vec![2, 5, 4, 10]), // organizationName
                    DerObject::UTF8String(b"Internet Widgits Pty Ltd"),
                ]),
            ]),
        ]
    );
    assert_eq!(parse_der(&bytes), IResult::Done(empty, expected));
}

//#[test]
//fn test_parse_hex4() {
//    let empty = &b""[..];
//    assert_eq!(parse_hex4(&[0x00, 0x01, 0x00, 0x01]), IResult::Done(empty, (65537)));
//}

#[test]
fn test_der_seq_iter() {
    let _ = env_logger::init();

    debug!("blah");

    let empty = &b""[..];
    let bytes = [ 0x30, 0x0a,
                  0x02, 0x03, 0x01, 0x00, 0x01,
                  0x02, 0x03, 0x01, 0x00, 0x00,
    ];
    let expected_values =
        vec![DerObject::Integer(65537), DerObject::Integer(65536)]
    ;
    let result = parse_der(&bytes);

    match result {
        IResult::Done(e,res) => {
            assert_eq!(e,empty);
            let mut idx = 0;
            // for v in res {
            //     debug!("v: {:?}", v);
            //     assert_eq!(v,expected_values[idx]);
            //     idx += 1;
            // }
            for v in res.ref_iter() {
                debug!("v: {:?}", v);
                assert_eq!((*v),expected_values[idx]);
                idx += 1;
            }
        },
        _ => assert_eq!(result,IResult::Done(empty,DerObject::Sequence(expected_values))),
    }
}


}

