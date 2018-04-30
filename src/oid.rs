//! Object ID (OID) representation

use std::fmt;
use std::slice;

/// Object ID (OID) representation
#[derive(PartialEq,Eq,Clone)]
pub struct Oid (Vec<u64>);

impl Oid {
    /// Build an OID from an array of `u64` integers
    pub fn from(s: &[u64]) -> Oid {
        Oid(s.to_owned())
    }

    /// Convert the OID to a string representation.
    /// The string contains the IDs separated by dots, for ex: "1.2.840.113549.1.1.5"
    pub fn to_string(&self) -> String {
        if self.0.is_empty() { return String::new(); }

        let mut s = self.0[0].to_string();

        for it in self.0.iter().skip(1) {
            s.push('.');
            s = s + &it.to_string();
        }

        s
    }

    /// Return an iterator on every ID
    pub fn iter(&self) -> slice::Iter<u64> {
        self.0.iter()
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.to_string())
    }
}

impl fmt::Debug for Oid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&format!("OID({})", self.to_string()))
    }
}




#[cfg(test)]
mod tests {
    use oid::Oid;

#[test]
fn test_oid_fmt() {
    let oid = Oid::from(&[1, 2, 840, 113549, 1, 1, 5]);
    assert_eq!(format!("{}",oid), "1.2.840.113549.1.1.5".to_owned());
}

}

