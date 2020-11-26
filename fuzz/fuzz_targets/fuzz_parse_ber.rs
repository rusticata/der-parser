#![no_main]
extern crate libfuzzer_sys;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    let _ = der_parser::parse_ber(data);
});
