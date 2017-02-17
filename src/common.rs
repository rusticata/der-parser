//const ASN1_CONSTRUCTED_FLAG: u8 = 0x20;
//
//#[repr(u8)]
//pub enum Tag {
//    Bool = 0x1,
//    Integer = 0x2,
//    BitString = 0x3,
//    OctetString = 0x4,
//    ObjectIdentifier = 0x6,
//    PrintableString = 0x13,
//    UTCTime = 0x17,
//    Sequence = (0x10 | ASN1_CONSTRUCTED_FLAG),
//}

#[derive(Debug)]
pub enum IntToEnumError {
    InvalidU8(u8),
    InvalidU16(u16),
}

#[macro_export]
macro_rules! error_if (
  ($i:expr, $cond:expr, $err:expr) => (
    {
      if $cond {
        IResult::Error($err)
      } else {
        IResult::Done($i, ())
      }
    }
  );
  ($i:expr, $cond:expr, $err:expr) => (
    error!($i, $cond, $err);
  );
);



pub fn bytes_to_u64(s: &[u8]) -> Result<u64, &'static str> {
    let mut u : u64 = 0;

    for &c in s {
        let (u1,f1) = u.overflowing_mul(256);
        let (u2,f2) = u1.overflowing_add(c as u64);
        if f1 || f2 { return Err("overflow"); }
        u = u2;
    }

    Ok(u)
}

#[macro_use]
macro_rules! parse_hex_to_u64 (
    ( $i:expr, $size:expr ) => (
        map_res!($i, take!(($size as usize)), $crate::bytes_to_u64)
    );
);

#[cfg(test)]
mod tests {
    use super::bytes_to_u64;

#[test]
fn test_bytes_to_u64() {
    let test1 = [0x00, 0x01, 0x02, 0x03];
    let expected1 : u64 = 0x010203;
    let res1 = bytes_to_u64(&test1);
    assert_eq!(res1,Ok(expected1));


    let test2 = [0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x01, 0x02, 0x03];
    let res2 = bytes_to_u64(&test2);
    assert_eq!(res2,Err("overflow"));
}

}
