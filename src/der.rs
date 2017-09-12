use std::vec::Vec;
use std::ops::Index;
//use nom::{IResult, space, alpha, alphanumeric, digit};
use nom::{be_u8,IResult,Err,ErrorKind};

use rusticata_macros::bytes_to_u64;
use oid::Oid;

#[derive(Debug,PartialEq)]
pub enum DerError {
    /// Der object does not have the expected type
    DerTypeError,
    DerValueError,

    /// Der integer is too large to fit in a native type. Use `as_bigint()`
    IntegerTooLarge,
}

/// Defined in X.680 section 8.4
#[derive(Debug,PartialEq)]
#[repr(u8)]
pub enum DerTag {
    EndOfContent = 0x0,
    Boolean = 0x1,
    Integer = 0x2,
    BitString = 0x3,
    OctetString = 0x4,
    Null = 0x05,
    Oid = 0x06,
    ObjDescriptor = 0x07,
    External = 0x08,
    RealType = 0x09,
    Enumerated = 0xa,
    EmbeddedPdv = 0xb,
    Utf8String = 0xc,
    RdvOid = 0xd,

    Sequence = 0x10,
    Set = 0x11,
    NumericString = 0x12,
    PrintableString = 0x13,
    T61String = 0x14,

    Ia5String = 0x16,
    UtcTime = 0x17,
    GeneralizedTime = 0x18,

    BmpString = 0x1e,

    Invalid = 0xff,
}

#[derive(Debug,Clone,PartialEq)]
pub struct DerObject<'a> {
    pub class: u8,
    pub structured: u8,
    pub tag: u8,

    pub content: DerObjectContent<'a>,
}

#[derive(Clone,Copy,Debug,PartialEq)]
pub struct DerElement {
    pub class: u8,
    pub structured: u8,
    pub tag: u8,
}

#[derive(Clone,Copy,Debug,PartialEq)]
pub struct DerElementHeader {
    pub elt: DerElement,
    pub len: u64,
}


#[derive(Debug,Clone,PartialEq)]
pub enum DerObjectContent<'a> {
    Boolean(bool),
    Integer(&'a[u8]),
    BitString(u8, &'a [u8]),
    OctetString(&'a [u8]),
    Null,
    Enum(u64),
    OID(Oid),
    NumericString(&'a[u8]),
    PrintableString(&'a[u8]),
    IA5String(&'a[u8]),
    UTF8String(&'a[u8]),
    T61String(&'a[u8]),

    BmpString(&'a[u8]),

    Sequence(Vec<DerObject<'a> >),
    Set(Vec<DerObject<'a> >),

    UTCTime(&'a [u8]),
    GeneralizedTime(&'a [u8]),

    ContextSpecific(/*tag:*/u8, Option<Box<DerObject<'a>>>),
    Unknown(&'a[u8]),
}

pub fn tag_of_der_content(c: &DerObjectContent) -> DerTag {
    match *c {
        DerObjectContent::Boolean(_)           => DerTag::Boolean,
        DerObjectContent::Integer(_)           => DerTag::Integer,
        DerObjectContent::BitString(_,_)       => DerTag::BitString,
        DerObjectContent::OctetString(_)       => DerTag::OctetString,
        DerObjectContent::Null                 => DerTag::Null,
        DerObjectContent::Enum(_)              => DerTag::Enumerated,
        DerObjectContent::OID(_)               => DerTag::Oid,
        DerObjectContent::NumericString(_)     => DerTag::NumericString,
        DerObjectContent::PrintableString(_)   => DerTag::PrintableString,
        DerObjectContent::IA5String(_)         => DerTag::Ia5String,
        DerObjectContent::UTF8String(_)        => DerTag::Utf8String,
        DerObjectContent::T61String(_)         => DerTag::T61String,
        DerObjectContent::BmpString(_)         => DerTag::BmpString,
        DerObjectContent::Sequence(_)          => DerTag::Sequence,
        DerObjectContent::Set(_)               => DerTag::Set,
        DerObjectContent::UTCTime(_)           => DerTag::UtcTime,
        DerObjectContent::GeneralizedTime(_)   => DerTag::GeneralizedTime,
        DerObjectContent::ContextSpecific(_,_) => DerTag::Invalid,
        DerObjectContent::Unknown(_)           => DerTag::Invalid,
    }
}

impl<'a> DerObject<'a> {
    pub fn from_header_and_content(hdr: DerElementHeader, c: DerObjectContent) -> DerObject {
        DerObject{
            class:      hdr.elt.class,
            structured: hdr.elt.structured,
            tag:        hdr.elt.tag,
            content:    c,
        }
    }
    /// Build a DerObject from its content, using default flags (no class, correct tag,
    /// and structured flag set only for Set and Sequence)
    pub fn from_obj(c: DerObjectContent) -> DerObject {
        let class = 0;
        let tag = tag_of_der_content(&c);
        let structured = match tag {
            DerTag::Sequence => 1,
            DerTag::Set      => 1,
            _                => 0,
        };
        DerObject{
            class:      class,
            structured: structured,
            tag:        tag as u8,
            content:    c,
        }
    }
    pub fn new_int(i: &'a[u8]) -> DerObject<'a> {
        DerObject{
            class:      0,
            structured: 0,
            tag:        DerTag::Integer as u8,
            content:    DerObjectContent::Integer(i),
        }
    }
}

impl<'a> DerObjectContent<'a> {
    pub fn as_u32(&self) -> Result<u32,DerError> {
        match self {
            &DerObjectContent::Integer(i) => {
                if i.len() <= 4 { bytes_to_u64(i).map(|x| x as u32).or(Err(DerError::DerTypeError)) }
                else { Err(DerError::IntegerTooLarge) }
            },
            &DerObjectContent::Enum(i)    => Ok(i as u32),
            _ => Err(DerError::DerTypeError),
        }
    }

    pub fn as_bool(&self) -> Result<bool,DerError> {
        match self {
            &DerObjectContent::Boolean(b) => Ok(b),
            _ => Err(DerError::DerTypeError),
        }
    }

    pub fn as_oid(&self) -> Result<&Oid,DerError> {
        match self {
            &DerObjectContent::OID(ref o) => Ok(o),
            _ => Err(DerError::DerTypeError),
        }
    }

    pub fn as_context_specific(&self) -> Result<(u8,Option<Box<DerObject<'a>>>),DerError> {
        match self {
            &DerObjectContent::ContextSpecific(u,ref o) => Ok((u,o.clone())),
            _ => Err(DerError::DerTypeError),
        }
    }

    pub fn as_sequence(&self) -> Result<&Vec<DerObject<'a>>,DerError> {
        match self {
            &DerObjectContent::Sequence(ref s) => Ok(s),
            _ => Err(DerError::DerTypeError),
        }
    }

    pub fn as_set(&self) -> Result<&Vec<DerObject<'a>>,DerError> {
        match self {
            &DerObjectContent::Set(ref s) => Ok(s),
            _ => Err(DerError::DerTypeError),
        }
    }

    pub fn as_slice(&self) -> Result<&'a [u8],DerError> {
        match self {
            &DerObjectContent::Integer(s)         => Ok(s),
            &DerObjectContent::BitString(_,s)     => Ok(s),
            &DerObjectContent::OctetString(s)     => Ok(s),
            &DerObjectContent::NumericString(s)   => Ok(s),
            &DerObjectContent::PrintableString(s) => Ok(s),
            &DerObjectContent::IA5String(s)       => Ok(s),
            &DerObjectContent::UTF8String(s)      => Ok(s),
            &DerObjectContent::T61String(s)       => Ok(s),
            &DerObjectContent::BmpString(s)       => Ok(s),
            &DerObjectContent::Unknown(s)         => Ok(s),
            _ => Err(DerError::DerTypeError),
        }
    }
}

#[cfg(feature="bigint")]
mod bigint {
    use super::{DerObject,DerObjectContent};
    use num::bigint::{Sign,BigInt,BigUint};

    impl<'a> DerObject<'a> {
        pub fn as_bigint(&self) -> Option<BigInt> {
            match self.content {
                DerObjectContent::Integer(s)         => Some(BigInt::from_bytes_be(Sign::Plus, s)),
                _ => None,
            }
        }

        pub fn as_biguint(&self) -> Option<BigUint> {
            match self.content {
                DerObjectContent::Integer(s)         => Some(BigUint::from_bytes_be(s)),
                _ => None,
            }
        }
    }
}

// This is a consuming iterator
impl<'a> IntoIterator for DerObject<'a> {
    type Item = DerObject<'a>;
    type IntoIter = DerObjectIntoIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        // match self {
        //     DerObjectContent::Sequence(ref v) => (),
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
            match self.val.content {
                DerObjectContent::Sequence(ref v) if self.idx < v.len() => Some(v[self.idx].clone()),
                DerObjectContent::Set(ref v) if self.idx < v.len() => Some(v[self.idx].clone()),
                _ => if self.idx == 0 { Some(self.val.clone()) } else { None },
            };
        self.idx += 1;
        res
    }
}

// impl<'a> Iterator for DerObjectContent<'a> {
//     type Item = DerObjectContent<'a>;
// 
//     fn next(&mut self) -> Option<DerObjectContent<'a>> {
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
        let res = match (*self.obj).content {
                DerObjectContent::Sequence(ref v) if self.idx < v.len() => Some(&v[self.idx]),
                DerObjectContent::Set(ref v) if self.idx < v.len() => Some(&v[self.idx]),
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
        match (*self).content {
            DerObjectContent::Sequence(ref v) if idx < v.len() => &v[idx],
            DerObjectContent::Set(ref v) if idx < v.len() => &v[idx],
            _ => panic!("Try to index DerObjectContent which is not structured"),
        }
        // XXX the following
        // self.ref_iter().nth(idx).unwrap()
        // fails with:
        // error: cannot infer an appropriate lifetime for autoref due to conflicting requirements [E0495]
        // self.ref_iter().nth(idx).unwrap()
    }
}


#[macro_export]
macro_rules! fold_parsers(
    ($i:expr, $($args:tt)*) => (
        {
            let parsers = [ $($args)* ];
            parsers.iter().fold(
                (IResult::Done($i,vec![])),
                |r, f| {
                    match r {
                        IResult::Done(rem,mut v) => {
                            map!(rem, f, |x| { v.push(x); v })
                        }
                        IResult::Incomplete(e) => IResult::Incomplete(e),
                        IResult::Error(e)      => IResult::Error(e),
                    }
                }
                )
        }
    );
);

#[macro_export]
macro_rules! parse_der_defined(
    ($i:expr, $ty:expr, $($args:tt)*) => (
        {
            let res =
            do_parse!(
                $i,
                hdr:     der_read_element_header >>
                         error_if!(hdr.elt.class != 0b00, Err::Code(ErrorKind::Custom(128))) >>
                         error_if!(hdr.elt.structured != 0b1, Err::Code(ErrorKind::Custom(129))) >>
                         error_if!(hdr.elt.tag != $ty, Err::Code(ErrorKind::Custom(130))) >>
                content: take!(hdr.len) >>
                ( (hdr,content) )
            );
            match res {
                IResult::Done(_rem,o)   => {
                    match fold_parsers!(o.1, $($args)* ) {
                        IResult::Done(rem,v)   => {
                            if rem.len() != 0 { IResult::Error(Err::Code(ErrorKind::Custom(131))) }
                            else { IResult::Done(_rem,(o.0,v)) }
                        },
                        IResult::Incomplete(e) => IResult::Incomplete(e),
                        IResult::Error(e)      => IResult::Error(e),
                    }
                },
                IResult::Incomplete(e) => IResult::Incomplete(e),
                IResult::Error(e)      => IResult::Error(e),
            }
        }
    );
);

#[macro_export]
macro_rules! parse_der_sequence_defined(
    ($i:expr, $($args:tt)*) => (
        map!(
            $i,
            parse_der_defined!(0x10, $($args)*),
            |(hdr,o)| DerObject::from_header_and_content(hdr,DerObjectContent::Sequence(o))
        )
    );
);

#[macro_export]
macro_rules! parse_der_set_defined(
    ($i:expr, $($args:tt)*) => (
        map!(
            $i,
            parse_der_defined!(0x11, $($args)*),
            |(hdr,o)| DerObject::from_header_and_content(hdr,DerObjectContent::Set(o))
        )
    );
);

#[macro_export]
macro_rules! parse_der_sequence_of(
    ($i:expr, $f:ident) => (
        do_parse!(
            $i,
            hdr:     der_read_element_header >>
                     error_if!(hdr.elt.tag != DerTag::Sequence as u8, Err::Code(ErrorKind::Custom(128))) >>
            content: flat_map!(take!(hdr.len),
                do_parse!(
                    r: many0!($f) >>
                       eof!() >>
                    ( r )
                )
            ) >>
            ( DerObject::from_header_and_content(hdr, DerObjectContent::Sequence(content)) )
        )
    )
);

#[macro_export]
macro_rules! parse_der_set_of(
    ($i:expr, $f:ident) => (
        do_parse!(
            $i,
            hdr:     der_read_element_header >>
                     error_if!(hdr.elt.tag != DerTag::Set as u8, Err::Code(ErrorKind::Custom(128))) >>
            content: flat_map!(take!(hdr.len),
                do_parse!(
                    r: many0!($f) >>
                       eof!() >>
                    ( r )
                )
            ) >>
            ( DerObject::from_header_and_content(hdr, DerObjectContent::Sequence(content)) )
        )
    )
);

#[macro_export]
macro_rules! parse_der_optional(
    ($i:expr, $f:ident) => (
        alt_complete!(
            $i,
            do_parse!(
                content: call!($f) >>
                (
                    DerObject::from_obj(
                        DerObjectContent::ContextSpecific(0 /* XXX */,Some(Box::new(content)))
                    )
                )
            ) |
            apply!(parse_der_explicit_failed,0 /* XXX */)
        )
    )
);








named!(parse_identifier<(&[u8],usize),DerElement>,
  do_parse!(
    class:      take_bits!(u8, 2) >>
    structured: take_bits!(u8, 1) >>
    tag:        take_bits!(u8, 5) >>
    ( DerElement{class:class,structured:structured,tag:tag} )
  )
);

named!(parse_der_length_byte<(&[u8],usize),(u8,u8)>,
  tuple!(
    take_bits!(u8, 1),
    take_bits!(u8, 7)
  )
);


fn der_read_oid<'a>(i: &'a[u8]) -> Result<Vec<u64>,u64> {
    let mut oid = Vec::new();
    let mut acc : u64;

    if i.len() == 0 { return Err(0); };

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

    match acc {
        0 => Ok(oid),
        _ => Err(acc),
    }
}


named!(pub der_read_element_header<&[u8],DerElementHeader>,
    do_parse!(
        el:   bits!( parse_identifier) >>
        len:  bits!( parse_der_length_byte) >>
        llen: cond!(len.0 == 1, take!(len.1)) >>

        ( {
            let len : u64 = match len.0 {
                0 => len.1 as u64,
                _ => {
                    match bytes_to_u64(llen.unwrap()) {
                        Ok(l)  => l,
                        Err(_) => { return IResult::Error(Err::Code(ErrorKind::Custom(128))); },
                    }
                },
            };
            DerElementHeader {
                elt: el,
                len: len,
            }
        } )
    )
);

named!(der_read_sequence_content<&[u8],Vec<DerObject> >,
    many0!(parse_der)
);

named!(der_read_set_content<&[u8],Vec<DerObject> >,
    many0!(parse_der)
);

/// Parse the next bytes as the content of a DER object.
///
/// Content type is *not* checked, caller is reponsible of providing the correct tag
pub fn der_read_element_content_as<'a,'b>(i:&'a[u8], tag:u8, len:usize) -> IResult<&'a [u8], DerObjectContent<'a>> {
    match tag {
        // 0x00 end-of-content
        // 0x01 bool
        0x01 => {
                    map!(i,
                        switch!(take!(1),
                          b"\x00" => value!(true) |
                          b"\xff" => value!(false)
                        ),
                        |b| { DerObjectContent::Boolean(b) }
                    )
                },
        // 0x02: integer
        0x02 => {
                    map!(i,
                        take!(len),
                        |i| { DerObjectContent::Integer(i) }
                    )
                },
        // 0x03: bitstring
        0x03 => {
                    do_parse!(i,
                        ignored_bits: be_u8 >>
                                      error_if!(len == 0, Err::Code(ErrorKind::LengthValue)) >>
                        s:            take!(len - 1) >> // XXX we must check if constructed or not (8.7)
                        ( DerObjectContent::BitString(ignored_bits,s) )
                    )
                },
        // 0x04: octetstring
        0x04 => {
                    map!(i,
                        take!(len), // XXX we must check if constructed or not (8.7)
                        |s| { DerObjectContent::OctetString(s) }
                    )
                },
        // 0x05: null
        0x05 => { IResult::Done(i,DerObjectContent::Null) },
        // 0x06: object identified
        0x06 => {
                    do_parse!(i,
                             error_if!(len == 0, Err::Code(ErrorKind::LengthValue)) >>
                        oid: map_res!(take!(len),der_read_oid) >>
                        ( DerObjectContent::OID(Oid::from_vec(&oid)) )
                    )
                },
        // 0x0a: enumerated
        0x0a => {
                    map!(i,
                        parse_hex_to_u64!(len),
                        |i| { DerObjectContent::Enum(i) }
                    )
                },
        // 0x0c: UTF8String
        0x0c => {
                    map!(i,
                        take!(len), // XXX we must check if constructed or not (8.7)
                        |s| { DerObjectContent::UTF8String(s) }
                    )
                },
        // 0x10: sequence
        0x10 => {
                    map!(i,
                        flat_map!(take!(len),der_read_sequence_content),
                        |l| { DerObjectContent::Sequence(l) }
                    )
                },
        // 0x11: set
        0x11 => {
                    map!(i,
                        flat_map!(take!(len),der_read_set_content),
                        |l| { DerObjectContent::Set(l) }
                    )
                },
        // 0x12: numericstring
        0x12 => {
                    map!(i,
                        take!(len), // XXX we must check if constructed or not (8.7)
                        |s| { DerObjectContent::NumericString(s) }
                    )
                },
        // 0x13: printablestring
        0x13 => {
                    map!(i,
                        take!(len), // XXX we must check if constructed or not (8.7)
                        |s| { DerObjectContent::PrintableString(s) }
                    )
                },
        // 0x14: t61string
        0x14 => {
                    map!(i,
                        take!(len), // XXX we must check if constructed or not (8.7)
                        |s| { DerObjectContent::T61String(s) }
                    )
                },

        // 0x16: ia5string
        0x16 => {
                    map!(i,
                        take!(len), // XXX we must check if constructed or not (8.7)
                        |s| { DerObjectContent::IA5String(s) }
                    )
                },
        // 0x17: utctime
        0x17 => {
                    map!(i,
                        take!(len), // XXX we must check if constructed or not (8.7)
                        |s| { DerObjectContent::UTCTime(s) }
                    )
                },
        // 0x18: utctime
        0x18 => {
                    map!(i,
                        take!(len), // XXX we must check if constructed or not (8.7)
                        |s| { DerObjectContent::GeneralizedTime(s) }
                    )
                },
                //
        // 0x1e: bmpstring
        0x1e => {
                    map!(i,
                        take!(len), // XXX we must check if constructed or not (8.7)
                        |s| { DerObjectContent::BmpString(s) }
                    )
                },
        // all unknown values
        _    => { IResult::Error(Err::Code(ErrorKind::Custom(130))) },
    }
}


pub fn der_read_element_content<'a,'b>(i: &'a[u8], hdr: DerElementHeader) -> IResult<&'a [u8], DerObject<'a>> {
    match hdr.elt.class {
        // universal
        0b00 => (),
        // application
        0b01 => (),
        // context-specific
        // 0b10 => return map!(
        //     i,
        //     // XXX nope, we cannot parse what's inside !
        //     flat_map!(take!(hdr.len),parse_der),
        //     |b| { DerObject::from_header_and_content(hdr,DerObjectContent::ContextSpecific(hdr.elt.tag,Some(Box::new(b)))) }
        // ),
        0b10 => return map!(
            i,
            take!(hdr.len),
            |b| { DerObject::from_header_and_content(hdr,DerObjectContent::Unknown(b)) }
        ),
        // private
        0b11 => (),
        _    => { return IResult::Error(Err::Code(ErrorKind::Custom(129))); },
    }
    match der_read_element_content_as(i, hdr.elt.tag, hdr.len as usize) {
        IResult::Done(rem,content) => {
            IResult::Done(rem, DerObject::from_header_and_content(hdr,content))
        },
        IResult::Error(Err::Code(ErrorKind::Custom(130))) => {
            map!(i,
                 take!(hdr.len),
                 |b| { DerObject::from_header_and_content(hdr,DerObjectContent::Unknown(b)) }
            )
        }
        IResult::Error(e) => IResult::Error(e),
        IResult::Incomplete(e) => IResult::Incomplete(e),
    }
}

pub fn parse_der_bool(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.elt.tag != DerTag::Boolean as u8, Err::Code(ErrorKind::Custom(128))) >>
       content: switch!(take!(1),
                        b"\x00" => value!(true) |
                        b"\xff" => value!(false)
       ) >>
       ( DerObject::from_header_and_content(hdr, DerObjectContent::Boolean(content)) )
   )
}

pub fn parse_der_integer(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.elt.tag != DerTag::Integer as u8, Err::Code(ErrorKind::Custom(128))) >>
       content: take!(hdr.len) >>
       ( DerObject::from_header_and_content(hdr, DerObjectContent::Integer(content)) )
   )
}

pub fn parse_der_bitstring(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:          der_read_element_header >>
                     error_if!(hdr.elt.tag != DerTag::BitString as u8, Err::Code(ErrorKind::Custom(128))) >>
       ignored_bits: be_u8 >>
                     error_if!(hdr.len < 1, Err::Code(ErrorKind::Custom(128))) >>
       content:      take!(hdr.len - 1) >> // XXX we must check if constructed or not (8.7)
       ( DerObject::from_header_and_content(hdr, DerObjectContent::BitString(ignored_bits,content)) )
   )
}

pub fn parse_der_octetstring(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.elt.tag != DerTag::OctetString as u8, Err::Code(ErrorKind::Custom(128))) >>
       content: take!(hdr.len) >> // XXX we must check if constructed or not (8.7)
       ( DerObject::from_header_and_content(hdr, DerObjectContent::OctetString(content)) )
   )
}

pub fn parse_der_null(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.elt.tag != DerTag::Null as u8, Err::Code(ErrorKind::Custom(128))) >>
       ( DerObject::from_header_and_content(hdr, DerObjectContent::Null) )
   )
}

pub fn parse_der_oid(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.elt.tag != DerTag::Oid as u8, Err::Code(ErrorKind::Custom(128))) >>
       content: map_res!(take!(hdr.len),der_read_oid) >>
       ( DerObject::from_header_and_content(hdr, DerObjectContent::OID(Oid::from_vec(&content))) )
   )
}

pub fn parse_der_enum(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.elt.tag != DerTag::Enumerated as u8, Err::Code(ErrorKind::Custom(128))) >>
       content: parse_hex_to_u64!(hdr.len) >>
       ( DerObject::from_header_and_content(hdr, DerObjectContent::Enum(content)) )
   )
}

pub fn parse_der_utf8string(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.elt.tag != DerTag::Utf8String as u8, Err::Code(ErrorKind::Custom(128))) >>
       content: take!(hdr.len) >> // XXX we must check if constructed or not (8.7)
       ( DerObject::from_header_and_content(hdr, DerObjectContent::UTF8String(content)) )
   )
}

pub fn parse_der_sequence(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.elt.tag != DerTag::Sequence as u8, Err::Code(ErrorKind::Custom(128))) >>
       content: flat_map!(take!(hdr.len),der_read_sequence_content) >>
       ( DerObject::from_header_and_content(hdr, DerObjectContent::Sequence(content)) )
   )
}

pub fn parse_der_set(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.elt.tag != DerTag::Set as u8, Err::Code(ErrorKind::Custom(128))) >>
       content: flat_map!(take!(hdr.len),der_read_set_content) >>
       ( DerObject::from_header_and_content(hdr, DerObjectContent::Set(content)) )
   )
}

pub fn parse_der_numericstring(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.elt.tag != DerTag::NumericString as u8, Err::Code(ErrorKind::Custom(128))) >>
       content: take!(hdr.len) >> // XXX we must check if constructed or not (8.7)
       ( DerObject::from_header_and_content(hdr, DerObjectContent::NumericString(content)) )
   )
}

pub fn parse_der_printablestring(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.elt.tag != DerTag::PrintableString as u8, Err::Code(ErrorKind::Custom(128))) >>
       content: take!(hdr.len) >> // XXX we must check if constructed or not (8.7)
       ( DerObject::from_header_and_content(hdr, DerObjectContent::PrintableString(content)) )
   )
}

pub fn parse_der_ia5string(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.elt.tag != DerTag::Ia5String as u8, Err::Code(ErrorKind::Custom(128))) >>
       content: take!(hdr.len) >> // XXX we must check if constructed or not (8.7)
       ( DerObject::from_header_and_content(hdr, DerObjectContent::IA5String(content)) )
   )
}

pub fn parse_der_t61string(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.elt.tag != DerTag::T61String as u8, Err::Code(ErrorKind::Custom(128))) >>
       content: take!(hdr.len) >> // XXX we must check if constructed or not (8.7)
       ( DerObject::from_header_and_content(hdr, DerObjectContent::T61String(content)) )
   )
}

pub fn parse_der_bmpstring(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.elt.tag != DerTag::BmpString as u8, Err::Code(ErrorKind::Custom(128))) >>
       content: take!(hdr.len) >> // XXX we must check if constructed or not (8.7)
       ( DerObject::from_header_and_content(hdr, DerObjectContent::BmpString(content)) )
   )
}

pub fn parse_der_utctime(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.elt.tag != DerTag::UtcTime as u8, Err::Code(ErrorKind::Custom(128))) >>
       content: take!(hdr.len) >> // XXX we must check if constructed or not (8.7)
       ( DerObject::from_header_and_content(hdr, DerObjectContent::UTCTime(content)) )
   )
}

pub fn parse_der_generalizedtime(i:&[u8]) -> IResult<&[u8],DerObject> {
   do_parse!(
       i,
       hdr:     der_read_element_header >>
                error_if!(hdr.elt.tag != DerTag::GeneralizedTime as u8, Err::Code(ErrorKind::Custom(128))) >>
       content: take!(hdr.len) >> // XXX we must check if constructed or not (8.7)
       ( DerObject::from_header_and_content(hdr, DerObjectContent::GeneralizedTime(content)) )
   )
}

pub fn parse_der_explicit_failed(i:&[u8], tag: u8) -> IResult<&[u8],DerObject,u32> {
    value!(i,DerObject::from_obj(DerObjectContent::ContextSpecific(tag,None)))
}

pub fn parse_der_explicit<F>(i:&[u8], tag: u8, f:F) -> IResult<&[u8],DerObject,u32>
    where F: Fn(&[u8]) -> IResult<&[u8],DerObject,u32>
{
    alt_complete!(
        i,
        do_parse!(
            hdr:     der_read_element_header >>
            error_if!(hdr.elt.tag != tag as u8, Err::Code(ErrorKind::Custom(127))) >>
            content: f >>
            (
                DerObject::from_header_and_content(
                    hdr,
                    DerObjectContent::ContextSpecific(tag,Some(Box::new(content)))
                )
            )
        ) |
        apply!(parse_der_explicit_failed,tag)
    )
}

/// call der *content* parsing function
pub fn parse_der_implicit<F>(i:&[u8], tag: u8, f:F) -> IResult<&[u8],DerObject,u32>
    where F: Fn(&[u8], u8, usize) -> IResult<&[u8],DerObjectContent,u32>
{
    alt_complete!(
        i,
        do_parse!(
            hdr:     der_read_element_header >>
            error_if!(hdr.elt.tag != tag as u8, Err::Code(ErrorKind::Custom(127))) >>
            content: map!(
                apply!(f, tag, hdr.len as usize),
                |b| { DerObject::from_obj(b) }
            ) >>
            (
                DerObject::from_header_and_content(
                    hdr,
                    DerObjectContent::ContextSpecific(tag,Some(Box::new(content)))
                )
            )
        ) |
        apply!(parse_der_explicit_failed,tag)
    )
}


named!(pub parse_der<&[u8],DerObject>,
    do_parse!(
        hdr:     der_read_element_header >>
                 // XXX safety check: length cannot be more than 2^32 bytes
                 error_if!(hdr.len > ::std::u32::MAX as u64, Err::Code(ErrorKind::Custom(127))) >>
        content: apply!(der_read_element_content,hdr) >>
        ( content )
    )
);

#[cfg(test)]
mod tests {
    use der::*;
    use nom::{IResult,Err,ErrorKind};

#[test]
fn test_der_bool() {
    let empty = &b""[..];
    let b_true  = DerObject::from_obj(DerObjectContent::Boolean(true));
    let b_false  = DerObject::from_obj(DerObjectContent::Boolean(false));
    assert_eq!(parse_der_bool(&[0x01, 0x01, 0x00]), IResult::Done(empty, b_true));
    assert_eq!(parse_der_bool(&[0x01, 0x01, 0xff]), IResult::Done(empty, b_false));
    let bytes = [0x01, 0x01, 0x7f];
    assert_eq!(parse_der_bool(&bytes[..]), IResult::Error(Err::Position(ErrorKind::Switch, &bytes[2..])));
}

#[test]
fn test_der_int() {
    let empty = &b""[..];
    let bytes = [0x02, 0x03, 0x01, 0x00, 0x01];
    let expected  = DerObject::from_obj(DerObjectContent::Integer(b"\x01\x00\x01"));
    assert_eq!(parse_der_integer(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_int_as_u32() {
    let val  = DerObject::from_obj(DerObjectContent::Integer(b"\x01\x00\x01"));
    assert_eq!(val.content.as_u32(), Ok(65537));
    let val  = DerObject::from_obj(DerObjectContent::Integer(b"\x01\x00\x01\x00\x01"));
    assert_eq!(val.content.as_u32(), Err(DerError::IntegerTooLarge));
}

#[test]
fn test_der_int_long() {
    let empty = &b""[..];
    let bytes = [0x02, 0x0a, 0x39, 0x11, 0x45, 0x10, 0x94, 0x39, 0x11, 0x45, 0x10, 0x94];
    let expected  = DerObject::from_obj(DerObjectContent::Integer(&bytes[2..]));
    assert_eq!(parse_der_integer(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_octetstring() {
    let empty = &b""[..];
    let bytes = [ 0x04, 0x05,
                  0x41, 0x41, 0x41, 0x41, 0x41,
    ];
    let expected  = DerObject::from_obj(DerObjectContent::OctetString(b"AAAAA"));
    assert_eq!(parse_der_octetstring(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_null() {
    let empty = &b""[..];
    let expected  = DerObject::from_obj(DerObjectContent::Null);
    assert_eq!(parse_der_null(&[0x05, 0x00]), IResult::Done(empty, expected));
}

#[test]
fn test_der_oid() {
    let empty = &b""[..];
    let bytes = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05];
    let expected  = DerObject::from_obj(DerObjectContent::OID(Oid::from(&[1, 2, 840, 113549, 1, 1, 5])));
    assert_eq!(parse_der_oid(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_enum() {
    let empty = &b""[..];
    let expected  = DerObject::from_obj(DerObjectContent::Enum(2));
    assert_eq!(parse_der_enum(&[0x0a, 0x01, 0x02]), IResult::Done(empty, expected));
}

#[test]
fn test_der_utf8string() {
    let empty = &b""[..];
    let bytes = [ 0x0c, 0x0a,
                  0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65
    ];
    let expected  = DerObject::from_obj(DerObjectContent::UTF8String(b"Some-State"));
    assert_eq!(parse_der_utf8string(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_seq() {
    let empty = &b""[..];
    let bytes = [ 0x30, 0x05,
                  0x02, 0x03, 0x01, 0x00, 0x01,
    ];
    let expected  = DerObject::from_obj(DerObjectContent::Sequence(vec![
        DerObject::new_int(b"\x01\x00\x01"),
    ]));
    assert_eq!(parse_der_sequence(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_set() {
    let empty = &b""[..];
    let bytes = [
        0x31, 0x05,
        0x02, 0x03, 0x01, 0x00, 0x01, // Integer 65537
    ];
    let expected  = DerObject::from_obj(DerObjectContent::Set(vec![
        DerObject::new_int(b"\x01\x00\x01"),
    ]));
    assert_eq!(parse_der(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_set_defined() {
    let empty = &b""[..];
    let bytes = [ 0x31, 0x0a,
                  0x02, 0x03, 0x01, 0x00, 0x01,
                  0x02, 0x03, 0x01, 0x00, 0x00,
    ];
    let expected  = DerObject::from_obj(DerObjectContent::Set(vec![
        DerObject::new_int(b"\x01\x00\x01"),
        DerObject::new_int(b"\x01\x00\x00"),
    ]));
    fn parser(i:&[u8]) -> IResult<&[u8],DerObject> {
        parse_der_set_defined!(i,
            parse_der_integer,
            parse_der_integer
        )
    };
    assert_eq!(parser(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_seq_defined() {
    let empty = &b""[..];
    let bytes = [ 0x30, 0x0a,
                  0x02, 0x03, 0x01, 0x00, 0x01,
                  0x02, 0x03, 0x01, 0x00, 0x00,
    ];
    let expected  = DerObject::from_obj(DerObjectContent::Sequence(vec![
        DerObject::new_int(b"\x01\x00\x01"),
        DerObject::new_int(b"\x01\x00\x00"),
    ]));
    fn parser(i:&[u8]) -> IResult<&[u8],DerObject> {
        parse_der_sequence_defined!(i,
            parse_der_integer,
            parse_der_integer
        )
    };
    assert_eq!(parser(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_seq_of() {
    let empty = &b""[..];
    let bytes = [ 0x30, 0x0a,
                  0x02, 0x03, 0x01, 0x00, 0x01,
                  0x02, 0x03, 0x01, 0x00, 0x00,
    ];
    let expected  = DerObject::from_obj(DerObjectContent::Sequence(vec![
        DerObject::new_int(b"\x01\x00\x01"),
        DerObject::new_int(b"\x01\x00\x00"),
    ]));
    fn parser(i:&[u8]) -> IResult<&[u8],DerObject> {
        parse_der_sequence_of!(i, parse_der_integer)
    };
    assert_eq!(parser(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_seq_of_incomplete() {
    let bytes = [ 0x30, 0x07,
                  0x02, 0x03, 0x01, 0x00, 0x01,
                  0x00, 0x00,
    ];
    fn parser(i:&[u8]) -> IResult<&[u8],DerObject> {
        parse_der_sequence_of!(i, parse_der_integer)
    };
    assert_eq!(parser(&bytes), IResult::Error(Err::Position(ErrorKind::Eof, &bytes[2..])));
}

#[test]
fn test_der_utctime() {
    let empty = &b""[..];
    let bytes = [0x17, 0x0D, 0x30, 0x32, 0x31, 0x32, 0x31, 0x33, 0x31, 0x34, 0x32, 0x39, 0x32, 0x33, 0x5A ];
    let expected = DerObject{
        class: 0,
        structured: 0,
        tag: DerTag::UtcTime as u8,
        content: DerObjectContent::UTCTime(&bytes[2..]),
    };
    assert_eq!(parse_der(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_generalizedtime() {
    let empty = &b""[..];
    let bytes = [0x18, 0x0D, 0x30, 0x32, 0x31, 0x32, 0x31, 0x33, 0x31, 0x34, 0x32, 0x39, 0x32, 0x33, 0x5A ];
    let expected = DerObject{
        class: 0,
        structured: 0,
        tag: DerTag::GeneralizedTime as u8,
        content: DerObjectContent::GeneralizedTime(&bytes[2..]),
    };
    assert_eq!(parse_der_generalizedtime(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_contextspecific() {
    let bytes = [0xa0, 0x03, 0x02, 0x01, 0x02];
    let empty = &b""[..];
    let expected = DerObject{
        class: 2,
        structured: 1,
        tag: 0,
        content: DerObjectContent::Unknown(&bytes[2..]),
    };
    assert_eq!(parse_der(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_explicit() {
    let empty = &b""[..];
    let bytes = [0xa0, 0x03, 0x02, 0x01, 0x02];
    let expected = DerObject{
        class: 2,
        structured: 1,
        tag: 0,
        content: DerObjectContent::ContextSpecific(0,Some(Box::new(DerObject::new_int(b"\x02")))),
    };
    assert_eq!(parse_der_explicit(&bytes, 0, parse_der_integer), IResult::Done(empty, expected));
    let expected2 = DerObject::from_obj(DerObjectContent::ContextSpecific(1,None));
    assert_eq!(parse_der_explicit(&bytes, 1, parse_der_integer), IResult::Done(&bytes[..], expected2));
}

#[test]
fn test_der_implicit() {
    let empty = &b""[..];
    let bytes = [0x81, 0x04, 0x70, 0x61, 0x73, 0x73];
    let pass = DerObject::from_obj(DerObjectContent::IA5String(b"pass"));
    let expected = DerObject{
        class: 2,
        structured: 0,
        tag: 1,
        content: DerObjectContent::ContextSpecific(1,Some(Box::new(pass))),
    };
    fn der_read_ia5string_content(i:&[u8], _tag:u8, len: usize) -> IResult<&[u8],DerObjectContent,u32> {
        der_read_element_content_as(i, DerTag::Ia5String as u8, len)
    }
    assert_eq!(parse_der_implicit(&bytes, 1, der_read_ia5string_content), IResult::Done(empty, expected));
    let expected2 = DerObject::from_obj(DerObjectContent::ContextSpecific(2,None));
    assert_eq!(parse_der_implicit(&bytes, 2, der_read_ia5string_content), IResult::Done(&bytes[..], expected2));
}

#[test]
fn test_der_optional() {
    let empty = &b""[..];
    let bytes1 = [ 0x30, 0x0a,
                  0x0a, 0x03, 0x00, 0x00, 0x01,
                  0x02, 0x03, 0x01, 0x00, 0x01,
    ];
    let bytes2 = [ 0x30, 0x05,
                  0x02, 0x03, 0x01, 0x00, 0x01,
    ];
    let expected1  = DerObject::from_obj(DerObjectContent::Sequence(vec![
        DerObject::from_obj(
            DerObjectContent::ContextSpecific(0, Some(Box::new(DerObject::from_obj(DerObjectContent::Enum(1)))))
        ),
        DerObject::new_int(b"\x01\x00\x01"),
    ]));
    let expected2  = DerObject::from_obj(DerObjectContent::Sequence(vec![
        DerObject::from_obj(
            DerObjectContent::ContextSpecific(0, None),
        ),
        DerObject::new_int(b"\x01\x00\x01"),
    ]));
    fn parse_optional_enum(i:&[u8]) -> IResult<&[u8],DerObject> {
        parse_der_optional!(i, parse_der_enum)
    }
    fn parser(i:&[u8]) -> IResult<&[u8],DerObject> {
        parse_der_sequence_defined!(i,
            parse_optional_enum,
            parse_der_integer
        )
    };
    assert_eq!(parser(&bytes1), IResult::Done(empty, expected1));
    assert_eq!(parser(&bytes2), IResult::Done(empty, expected2));
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
    let expected = DerObject::from_obj(
        DerObjectContent::Sequence(
            vec![
                DerObject::from_obj(DerObjectContent::Set(vec![
                    DerObject::from_obj(DerObjectContent::Sequence(vec![
                        DerObject::from_obj(DerObjectContent::OID(Oid::from(&[2, 5, 4, 6]))), // countryName
                        DerObject::from_obj(DerObjectContent::PrintableString(b"FR")),
                    ])),
                ])),
                DerObject::from_obj(DerObjectContent::Set(vec![
                    DerObject::from_obj(DerObjectContent::Sequence(vec![
                        DerObject::from_obj(DerObjectContent::OID(Oid::from(&[2, 5, 4, 8]))), // stateOrProvinceName
                        DerObject::from_obj(DerObjectContent::UTF8String(b"Some-State")),
                    ])),
                ])),
                DerObject::from_obj(DerObjectContent::Set(vec![
                    DerObject::from_obj(DerObjectContent::Sequence(vec![
                        DerObject::from_obj(DerObjectContent::OID(Oid::from(&[2, 5, 4, 10]))), // organizationName
                        DerObject::from_obj(DerObjectContent::UTF8String(b"Internet Widgits Pty Ltd")),
                    ])),
                ])),
            ]
        )
    );
    assert_eq!(parse_der(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_seq_dn_defined() {
    let empty = &b""[..];
    let bytes = [
        0x30, 0x45, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
        0x02, 0x46, 0x52, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08,
        0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65,
        0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49,
        0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67,
        0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64
    ];
    let expected = DerObject::from_obj(
        DerObjectContent::Sequence(
            vec![
                DerObject::from_obj(DerObjectContent::Set(vec![
                    DerObject::from_obj(DerObjectContent::Sequence(vec![
                        DerObject::from_obj(DerObjectContent::OID(Oid::from(&[2, 5, 4, 6]))), // countryName
                        DerObject::from_obj(DerObjectContent::PrintableString(b"FR")),
                    ])),
                ])),
                DerObject::from_obj(DerObjectContent::Set(vec![
                    DerObject::from_obj(DerObjectContent::Sequence(vec![
                        DerObject::from_obj(DerObjectContent::OID(Oid::from(&[2, 5, 4, 8]))), // stateOrProvinceName
                        DerObject::from_obj(DerObjectContent::UTF8String(b"Some-State")),
                    ])),
                ])),
                DerObject::from_obj(DerObjectContent::Set(vec![
                    DerObject::from_obj(DerObjectContent::Sequence(vec![
                        DerObject::from_obj(DerObjectContent::OID(Oid::from(&[2, 5, 4, 10]))), // organizationName
                        DerObject::from_obj(DerObjectContent::UTF8String(b"Internet Widgits Pty Ltd")),
                    ])),
                ])),
            ]
        )
    );
    #[inline]
    fn parse_directory_string(i:&[u8]) -> IResult<&[u8],DerObject> {
        alt!(i, parse_der_utf8string | parse_der_printablestring | parse_der_ia5string)
    }
    #[inline]
    fn parse_attr_type_and_value(i:&[u8]) -> IResult<&[u8],DerObject> {
        parse_der_sequence_defined!(i,
            parse_der_oid,
            parse_directory_string
        )
    };
    #[inline]
    fn parse_rdn(i:&[u8]) -> IResult<&[u8],DerObject> {
        parse_der_set_defined!(i, parse_attr_type_and_value)
    }
    #[inline]
    fn parse_name(i:&[u8]) -> IResult<&[u8],DerObject> {
        parse_der_sequence_defined!(i,
            parse_rdn,
            parse_rdn,
            parse_rdn
        )
    }
    assert_eq!(parse_name(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_seq_iter() {
    let empty = &b""[..];
    let bytes = [ 0x30, 0x0a,
                  0x02, 0x03, 0x01, 0x00, 0x01,
                  0x02, 0x03, 0x01, 0x00, 0x00,
    ];
    let expected_values = vec![
        DerObject::new_int(b"\x01\x00\x01"),
        DerObject::new_int(b"\x01\x00\x00"),
    ];
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
                println!("v: {:?}", v);
                assert_eq!((*v),expected_values[idx]);
                idx += 1;
            }
        },
        _ => assert_eq!(result,IResult::Done(empty,DerObject::from_obj(DerObjectContent::Sequence(expected_values)))),
    }
}

#[cfg(feature="bigint")]
#[test]
fn test_der_to_bigint() {
    let obj  = DerObject::from_obj(DerObjectContent::Integer(b"\x01\x00\x01"));
    let expected = ::num::bigint::BigInt::from(0x10001);

    assert_eq!(obj.as_bigint(), Some(expected));
}

#[cfg(feature="bigint")]
#[test]
fn test_der_to_biguint() {
    let obj  = DerObject::from_obj(DerObjectContent::Integer(b"\x01\x00\x01"));
    let expected = ::num::bigint::BigUint::from(0x10001 as u32);

    assert_eq!(obj.as_biguint(), Some(expected));
}

}

