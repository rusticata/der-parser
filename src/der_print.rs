use std::fmt;
use std::str;
use der::{DerObject,DerObjectContent,BitStringObject};

use rusticata_macros::debug;

#[derive(Clone,PartialEq)]
pub enum PrettyPrinterFlag {
    ShowHeader,
}

pub struct PrettyDer<'a> {
    obj:     &'a DerObject<'a>,
    indent:  usize,
    inc:     usize,

    flags:   Vec<PrettyPrinterFlag>,
}

impl<'a> DerObject<'a> {
    pub fn as_pretty(&'a self, indent:usize, increment:usize) -> PrettyDer<'a> {
        PrettyDer{
            obj:     self,
            indent:  indent,
            inc:     increment,

            flags:   Vec::new(),
        }
    }
}

impl<'a> PrettyDer<'a> {
    pub fn set_flag(&mut self, flag: PrettyPrinterFlag) {
        if ! self.flags.contains(&flag) {
            self.flags.push(flag);
        }
    }

    pub fn next_indent<'b>(&self, obj: &'b DerObject) -> PrettyDer<'b> {
        PrettyDer{
            obj:     obj,
            indent:  self.indent + self.inc,
            inc:     self.inc,
            flags:   self.flags.to_vec(),
        }
    }
}

impl<'a> fmt::Debug for PrettyDer<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.indent > 0 {
            try!(write!(f, "{:1$}", " ", self.indent));
        };
        if self.flags.contains(&PrettyPrinterFlag::ShowHeader) {
            try!(write!(f, "[c:{}, s:{}, t:{}] ", self.obj.class, self.obj.structured, self.obj.tag));
        };
        fn print_utf8_string_with_type(f: &mut fmt::Formatter, s: &[u8], ty: &str) -> fmt::Result {
            match str::from_utf8(s) {
                Ok(b)  => writeln!(f, "{}(\"{}\")", ty, b),
                Err(e) => writeln!(f, "{}({:?}) <error decoding utf8 string: {:?}>", ty, s, e),
            }
        }
        match self.obj.content {
            DerObjectContent::Boolean(b)             => writeln!(f, "Boolean({:?})", b),
            DerObjectContent::Integer(i)             => writeln!(f, "Integer({:?})", debug::HexSlice{d:i}),
            DerObjectContent::Enum(i)                => writeln!(f, "Enum({})", i),
            DerObjectContent::OID(ref v)             => writeln!(f, "OID({:?})", v),
            DerObjectContent::Null                   => writeln!(f, "Null"),
            DerObjectContent::OctetString(v)         => writeln!(f, "OctetString({:?})", debug::HexSlice{d:v}),
            DerObjectContent::BitString(u,BitStringObject{data:v})
                                                     => writeln!(f, "BitString({},{:?})", u, debug::HexSlice{d:v}),
            DerObjectContent::GeneralizedTime(s)     => print_utf8_string_with_type(f, s, "GeneralizedTime"),
            DerObjectContent::UTCTime(s)             => print_utf8_string_with_type(f, s, "UTCTime"),
            DerObjectContent::PrintableString(s)     => print_utf8_string_with_type(f, s, "PrintableString"),
            DerObjectContent::NumericString(s)       => print_utf8_string_with_type(f, s, "NumericString"),
            DerObjectContent::UTF8String(s)          => print_utf8_string_with_type(f, s, "UTF8String"),
            DerObjectContent::IA5String(s)           => print_utf8_string_with_type(f, s, "IA5String"),
            DerObjectContent::T61String(s)           => print_utf8_string_with_type(f, s, "T61String"),
            DerObjectContent::BmpString(s)           => print_utf8_string_with_type(f, s, "BmpString"),
            DerObjectContent::GeneralString(s)       => print_utf8_string_with_type(f, s, "GeneralString"),
            DerObjectContent::ContextSpecific(n,ref o) => {
                let new_indent = self.indent + self.inc;
                writeln!(f, "ContextSpecific [{}] {{", n)?;
                match *o {
                    Some(ref obj) => write!(f, "{:?}", self.next_indent(obj))?,
                    None          => writeln!(f, "{:1$}None", " ", new_indent)?,
                };
                if self.indent > 0 {
                    write!(f, "{:1$}", " ", self.indent)?;
                };
                writeln!(f, "}}")?;
                Ok(())
            },
            DerObjectContent::Set(ref v) |
            DerObjectContent::Sequence(ref v)        => {
                let ty = if self.obj.tag == 0x10 { "Sequence" } else { "Set" };
                writeln!(f, "{}[", ty)?;
                for o in v {
                    write!(f, "{:?}", self.next_indent(o))?;
                };
                if self.indent > 0 {
                    write!(f, "{:1$}", " ", self.indent)?;
                };
                writeln!(f, "]")?;
                Ok(())
            },
            DerObjectContent::Unknown(o)             => writeln!(f, "Unknown({:?})", o),
        }
    }
}

#[cfg(test)]
mod tests {
    use der::*;
    use super::PrettyPrinterFlag;

#[test]
fn test_pretty_print() {
    let d = DerObject::from_obj(DerObjectContent::Sequence(vec![
        DerObject::from_int_slice(b"\x01\x00\x01"),
        DerObject::from_int_slice(b"\x01\x00\x01"),
        DerObject::from_obj(DerObjectContent::Set(vec![
            DerObject::from_int_slice(b"\x01"),
            DerObject::from_int_slice(b"\x02"),
        ]))
    ]));

    println!("{:?}", d.as_pretty(0,2));

    let mut pp = d.as_pretty(0,4);
    pp.set_flag(PrettyPrinterFlag::ShowHeader);
    println!("{:?}", pp);
}

}

