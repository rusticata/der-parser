use std::fmt;
use std::slice;

#[derive(PartialEq,Eq,Clone)]
pub struct Oid (Vec<u64>);

impl Oid {
    pub fn from(s: &[u64]) -> Oid {
        let v : Vec<u64> = s.iter().fold(
            Vec::new(),
            |mut acc,i| { acc.push(*i); acc }
        );
        Oid(v)
    }

    pub fn from_vec(v: &Vec<u64>) -> Oid {
        Oid(v.clone())
    }

    pub fn to_hex(&self) -> String {
        if self.0.len() == 0 { return String::new(); }

        let mut s = self.0[0].to_string();

        for it in self.0.iter().skip(1) {
            s.push('.');
            s = s + &it.to_string();
        }

        s
    }

    pub fn iter(&self) -> slice::Iter<u64> {
        self.0.iter()
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Oid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&format!("OID({})", self.to_hex()))
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

