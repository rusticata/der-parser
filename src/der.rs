use std::vec::Vec;
use std::ops::Index;
use std::convert::From;
use std::convert::AsRef;
//use nom::{IResult, space, alpha, alphanumeric, digit};

use rusticata_macros::bytes_to_u64;
use oid::Oid;
use error::DerError;

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

    GeneralString = 27, // 0x1b

    BmpString = 0x1e,

    Invalid = 0xff,
}

/// Representation of a DER-encoded (X.690) object
#[derive(Debug,Clone,PartialEq)]
pub struct DerObject<'a> {
    pub class: u8,
    pub structured: u8,
    pub tag: u8,

    pub content: DerObjectContent<'a>,
}

#[derive(Clone,Copy,Debug,PartialEq)]
pub struct DerObjectHeader {
    pub class: u8,
    pub structured: u8,
    pub tag: u8,
    pub len: u64,
}


#[derive(Debug,Clone,PartialEq)]
pub enum DerObjectContent<'a> {
    Boolean(bool),
    Integer(&'a[u8]),
    BitString(u8, BitStringObject<'a>),
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

    GeneralString(&'a [u8]),

    ContextSpecific(/*tag:*/u8, Option<Box<DerObject<'a>>>),
    Unknown(&'a[u8]),
}

impl DerObjectHeader {
    /// Test if object class is Universal
    pub fn is_universal(&self) -> bool { self.class == 0 }
    /// Test if object class is Application
    pub fn is_application(&self) -> bool { self.class == 0b01 }
    /// Test if object class is Context-specific
    pub fn is_contextspecific(&self) -> bool { self.class == 0b10 }
    /// Test if object class is Private
    pub fn is_private(&self) -> bool { self.class == 0b11 }

    /// Test if object is primitive
    pub fn is_primitive(&self) -> bool { self.structured == 0 }
    /// Test if object is constructed
    pub fn is_constructed(&self) -> bool { self.structured == 1 }
}

impl<'a> DerObject<'a> {
    /// Build a DerObject from a header and content.
    /// Note: values are not checked, so the tag can be different from the real content, or flags
    /// can be invalid.
    pub fn from_header_and_content(hdr: DerObjectHeader, c: DerObjectContent) -> DerObject {
        DerObject{
            class:      hdr.class,
            structured: hdr.structured,
            tag:        hdr.tag,
            content:    c,
        }
    }
    /// Build a DerObject from its content, using default flags (no class, correct tag,
    /// and structured flag set only for Set and Sequence)
    pub fn from_obj(c: DerObjectContent) -> DerObject {
        let class = 0;
        let tag = c.tag();
        let structured = match tag {
            DerTag::Sequence |
            DerTag::Set      => 1,
            _                => 0,
        };
        DerObject{
            class,
            structured,
            tag:        tag as u8,
            content:    c,
        }
    }

    /// Build a DER integer object from a slice containing an encoded integer
    pub fn from_int_slice(i: &'a[u8]) -> DerObject<'a> {
        DerObject{
            class:      0,
            structured: 0,
            tag:        DerTag::Integer as u8,
            content:    DerObjectContent::Integer(i),
        }
    }

    /// Build a DER sequence object from a vector of DER objects
    pub fn from_seq(l:Vec<DerObject>) -> DerObject {
        DerObject::from_obj( DerObjectContent::Sequence(l) )
    }

    /// Build a DER set object from a vector of DER objects
    pub fn from_set(l:Vec<DerObject>) -> DerObject {
        DerObject::from_obj( DerObjectContent::Set(l) )
    }

    /// Attempt to read integer value from DER object.
    /// This can fail if the object is not an integer, or if it is too large.
    ///
    /// ```rust,no_run
    /// # extern crate der_parser;
    /// # use der_parser::{DerObject,DerObjectContent};
    /// # fn main() {
    /// let der_int  = DerObject::from_obj(DerObjectContent::Integer(b"\x01\x00\x01"));
    /// assert_eq!(
    ///     der_int.as_u64(),
    ///     Ok(0x10001)
    /// );
    /// # }
    /// ```
    pub fn as_u64(&self) -> Result<u64,DerError> { self.content.as_u64() }

    /// Attempt to read integer value from DER object.
    /// This can fail if the object is not an integer, or if it is too large.
    ///
    /// ```rust,no_run
    /// # extern crate der_parser;
    /// # use der_parser::{DerObject,DerObjectContent};
    /// # fn main() {
    /// let der_int  = DerObject::from_obj(DerObjectContent::Integer(b"\x01\x00\x01"));
    /// assert_eq!(
    ///     der_int.as_u32(),
    ///     Ok(0x10001)
    /// );
    /// # }
    /// ```
    pub fn as_u32(&self) -> Result<u32,DerError> { self.content.as_u32() }

    /// Attempt to read integer value from DER object.
    /// This can fail if the object is not a boolean.
    pub fn as_bool(&self) -> Result<bool,DerError> { self.content.as_bool() }

    /// Attempt to read an OID value from DER object.
    /// This can fail if the object is not an OID.
    ///
    /// Note that this function returns a reference to the OID. To get an owned value,
    /// use [`as_oid_val`](struct.DerObject.html#method.as_oid_val)
    pub fn as_oid(&self) -> Result<&Oid,DerError> { self.content.as_oid() }

    /// Attempt to read an OID value from DER object.
    /// This can fail if the object is not an OID.
    pub fn as_oid_val(&self) -> Result<Oid,DerError> { self.content.as_oid_val() }

    /// Attempt to read the content from a context-specific DER object.
    /// This can fail if the object is not context-specific.
    ///
    /// Note: the object is cloned.
    pub fn as_context_specific(&self) -> Result<(u8,Option<Box<DerObject<'a>>>),DerError> {
        self.content.as_context_specific()
    }

    /// Attempt to read a reference to a BitString value from DER object.
    /// This can fail if the object is not an BitString.
    ///
    /// Note that this function returns a reference to the BitString. To get an owned value,
    /// use [`as_bitstring`](struct.DerObject.html#method.as_bitstring)
    pub fn as_bitstring_ref(&self) -> Result<&BitStringObject,DerError> { self.content.as_bitstring_ref() }

    /// Attempt to read a BitString value from DER object.
    /// This can fail if the object is not an BitString.
    pub fn as_bitstring(&'a self) -> Result<BitStringObject<'a>,DerError> { self.content.as_bitstring() }

    /// Attempt to extract the list of objects from a DER sequence.
    /// This can fail if the object is not a sequence.
    pub fn as_sequence(&self) -> Result<&Vec<DerObject<'a>>,DerError> {
        self.content.as_sequence()
    }

    /// Attempt to extract the list of objects from a DER set.
    /// This can fail if the object is not a set.
    pub fn as_set(&self) -> Result<&Vec<DerObject<'a>>,DerError> {
        self.content.as_set()
    }

    /// Attempt to get the content from a DER object, as a slice.
    /// This can fail if the object does not contain a type directly equivalent to a slice (e.g a
    /// sequence).
    /// This function mostly concerns string types, integers, or unknown DER objects.
    pub fn as_slice(&self) -> Result<&'a [u8],DerError> { self.content.as_slice() }

    /// Test if object class is Universal
    pub fn is_universal(&self) -> bool { self.class == 0 }
    /// Test if object class is Application
    pub fn is_application(&self) -> bool { self.class == 0b01 }
    /// Test if object class is Context-specific
    pub fn is_contextspecific(&self) -> bool { self.class == 0b10 }
    /// Test if object class is Private
    pub fn is_private(&self) -> bool { self.class == 0b11 }

    /// Test if object is primitive
    pub fn is_primitive(&self) -> bool { self.structured == 0 }
    /// Test if object is constructed
    pub fn is_constructed(&self) -> bool { self.structured == 1 }
}

/// Build a DER object from an OID.
impl<'a> From<Oid> for DerObject<'a> {
    fn from(oid: Oid) -> DerObject<'a> {
        DerObject::from_obj(DerObjectContent::OID(oid))
    }
}

/// Build a DER object from a DerObjectContent.
impl<'a> From<DerObjectContent<'a>> for DerObject<'a> {
    fn from(obj: DerObjectContent<'a>) -> DerObject<'a> {
        DerObject::from_obj(obj)
    }
}

impl<'a> DerObjectContent<'a> {
    pub fn as_u64(&self) -> Result<u64,DerError> {
        match *self {
            DerObjectContent::Integer(i) => {
                bytes_to_u64(i).or(Err(DerError::IntegerTooLarge))
            },
            DerObjectContent::Enum(i)    => Ok(i as u64),
            _ => Err(DerError::DerTypeError),
        }
    }

    pub fn as_u32(&self) -> Result<u32,DerError> {
        match *self {
            DerObjectContent::Integer(i) => {
                if i.len() <= 4 { bytes_to_u64(i).map(|x| x as u32).or(Err(DerError::DerTypeError)) }
                else { Err(DerError::IntegerTooLarge) }
            },
            DerObjectContent::Enum(i)    => Ok(i as u32),
            _ => Err(DerError::DerTypeError),
        }
    }

    pub fn as_bool(&self) -> Result<bool,DerError> {
        match *self {
            DerObjectContent::Boolean(b) => Ok(b),
            _ => Err(DerError::DerTypeError),
        }
    }

    pub fn as_oid(&self) -> Result<&Oid,DerError> {
        match *self {
            DerObjectContent::OID(ref o) => Ok(o),
            _ => Err(DerError::DerTypeError),
        }
    }

    pub fn as_oid_val(&self) -> Result<Oid,DerError> {
        match *self {
            DerObjectContent::OID(ref o) => Ok(o.to_owned()),
            _ => Err(DerError::DerTypeError),
        }
    }

    pub fn as_context_specific(&self) -> Result<(u8,Option<Box<DerObject<'a>>>),DerError> {
        match *self {
            DerObjectContent::ContextSpecific(u,ref o) => Ok((u,o.clone())),
            _ => Err(DerError::DerTypeError),
        }
    }

    pub fn as_bitstring_ref(&self) -> Result<&BitStringObject,DerError> {
        match *self {
            DerObjectContent::BitString(_, ref b) => Ok(b),
            _ => Err(DerError::DerTypeError),
        }
    }

    pub fn as_bitstring(&'a self) -> Result<BitStringObject<'a>,DerError> {
        match *self {
            DerObjectContent::BitString(_, ref b) => Ok(b.to_owned()),
            _ => Err(DerError::DerTypeError),
        }
    }

    pub fn as_sequence(&self) -> Result<&Vec<DerObject<'a>>,DerError> {
        match *self {
            DerObjectContent::Sequence(ref s) => Ok(s),
            _ => Err(DerError::DerTypeError),
        }
    }

    pub fn as_set(&self) -> Result<&Vec<DerObject<'a>>,DerError> {
        match *self {
            DerObjectContent::Set(ref s) => Ok(s),
            _ => Err(DerError::DerTypeError),
        }
    }

    pub fn as_slice(&self) -> Result<&'a [u8],DerError> {
        match *self {
            DerObjectContent::Integer(s) |
            DerObjectContent::BitString(_,BitStringObject{data:s}) |
            DerObjectContent::OctetString(s) |
            DerObjectContent::NumericString(s) |
            DerObjectContent::PrintableString(s) |
            DerObjectContent::IA5String(s) |
            DerObjectContent::UTF8String(s) |
            DerObjectContent::T61String(s) |
            DerObjectContent::BmpString(s) |
            DerObjectContent::GeneralString(s) |
            DerObjectContent::Unknown(s)         => Ok(s),
            _ => Err(DerError::DerTypeError),
        }
    }

    pub fn tag(&self) -> DerTag {
        match *self {
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
            DerObjectContent::GeneralString(_)     => DerTag::GeneralString,
            DerObjectContent::ContextSpecific(_,_) |
            DerObjectContent::Unknown(_)           => DerTag::Invalid,
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
        DerObjectRefIterator{ obj:self, idx:0 }
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

/// BitString wrapper
#[derive(Clone, Debug,PartialEq)]
pub struct BitStringObject<'a> {
    pub data: &'a[u8],
}

impl<'a> BitStringObject<'a> {
    /// Test if bit `bitnum` is set
    pub fn is_set(&self, bitnum:usize) -> bool {
        let byte_pos = bitnum / 8;
        if byte_pos >= self.data.len () {
            return false;
        }
        let b = 7 - (bitnum % 8);
        (self.data[byte_pos] & (1 << b)) != 0
    }
}

impl<'a> AsRef<[u8]> for BitStringObject<'a> {
    fn as_ref(&self) -> &[u8] { self.data }
}



#[cfg(test)]
mod tests {
    use der::*;

#[test]
fn test_der_as_u64() {
    let der_obj  = DerObject::from_int_slice(b"\x01\x00\x02");
    assert_eq!(der_obj.as_u64(), Ok(0x10002));
}

#[test]
fn test_der_seq_iter() {
    let der_obj  = DerObject::from_obj(DerObjectContent::Sequence(vec![
        DerObject::from_int_slice(b"\x01\x00\x01"),
        DerObject::from_int_slice(b"\x01\x00\x00"),
    ]));
    let expected_values = vec![
        DerObject::from_int_slice(b"\x01\x00\x01"),
        DerObject::from_int_slice(b"\x01\x00\x00"),
    ];

    let mut idx = 0;
    // for v in res {
    //     debug!("v: {:?}", v);
    //     assert_eq!(v,expected_values[idx]);
    //     idx += 1;
    // }
    for v in der_obj.ref_iter() {
        println!("v: {:?}", v);
        assert_eq!((*v),expected_values[idx]);
        idx += 1;
    }
}

#[test]
fn test_der_from_oid() {
    let obj : DerObject = Oid::from(&[1,2]).into();
    let expected = DerObject::from_obj(DerObjectContent::OID(Oid::from(&[1,2])));

    assert_eq!(obj, expected);
}

#[test]
fn test_der_bistringobject() {
    let obj = BitStringObject{ data: &[0x0f, 0x00, 0x40] };
    assert!(!obj.is_set(0));
    assert!(obj.is_set(7));
    assert!(!obj.is_set(9));
    assert!(obj.is_set(17));
}

#[test]
fn test_der_bistringobject_asref() {
    fn assert_equal<T: AsRef<[u8]>>(s: T, b: &[u8]) {
       assert_eq!(s.as_ref(), b);
    }
    let b: &[u8] = &[0x0f, 0x00, 0x40];
    let obj = BitStringObject{data:b};
    assert_equal(obj, b);
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

