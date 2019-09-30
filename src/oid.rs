//! Object ID (OID) representation

use std::fmt;
use std::slice;

use std::num::ParseIntError;
use std::str::FromStr;

/// Object ID (OID) representation
#[derive(PartialEq, Eq, Clone)]
pub struct Oid(Vec<u64>);

impl Oid {
    /// Build an OID from an array of `u64` integers
    pub fn from(s: &[u64]) -> Oid {
        Oid(s.to_owned())
    }

    /// Return an iterator on every ID
    pub fn iter(&self) -> slice::Iter<u64> {
        self.0.iter()
    }
}

impl fmt::Display for Oid {
    /// Convert the OID to a string representation.
    /// The string contains the IDs separated by dots, for ex: "1.2.840.113549.1.1.5"
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.0.is_empty() {
            return Ok(());
        }
        write!(f, "{}", self.0[0])?;
        for it in self.0.iter().skip(1) {
            write!(f, ".{}", it)?;
        }
        Ok(())
    }
}

impl fmt::Debug for Oid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&format!("OID({})", self.to_string()))
    }
}

impl FromStr for Oid {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v: Result<Vec<_>, ParseIntError> = s.split('.').map(|c| c.parse::<u64>()).collect();
        v.map(Oid)
    }
}

#[cfg(test)]
mod tests {
    use crate::oid::Oid;
    use std::str::FromStr;

    #[test]
    fn test_oid_fmt() {
        let oid = Oid::from(&[1, 2, 840, 113_549, 1, 1, 5]);
        assert_eq!(format!("{}", oid), "1.2.840.113549.1.1.5".to_owned());
        assert_eq!(format!("{:?}", oid), "OID(1.2.840.113549.1.1.5)".to_owned());
    }

    #[test]
    fn test_oid_from_str() {
        let oid_ref = Oid::from(&[1, 2, 840, 113_549, 1, 1, 5]);
        let oid = Oid::from_str("1.2.840.113549.1.1.5").unwrap();
        assert_eq!(oid_ref, oid);
    }
}
