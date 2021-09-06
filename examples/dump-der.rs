use der_parser::ber::*;
use der_parser::der::*;
use std::env;
use std::io;

pub fn main() -> io::Result<()> {
    let mut parse_as_ber = false;
    for file_name in env::args().skip(1) {
        match file_name.as_ref() {
            "--ber" => {
                parse_as_ber = true;
                continue;
            }
            "--der" => {
                parse_as_ber = false;
                continue;
            }
            _ => (),
        }
        let data = std::fs::read(file_name.clone()).expect("Unable to read file");
        let (rem, obj) = if parse_as_ber {
            parse_ber(&data).expect("could not parse BER data")
        } else {
            parse_der(&data).expect("could not parse DER data")
        };
        println!("{:?}", obj.as_pretty(0, 2));
        if !rem.is_empty() {
            println!("WARNING: extra bytes after BER/DER object:\n{:x?}", rem);
        }
    }
    Ok(())
}
