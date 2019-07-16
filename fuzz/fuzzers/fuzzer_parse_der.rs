#![no_main]
extern crate der_parser;
extern crate libfuzzer_sys;
#[export_name = "rust_fuzzer_test_input"]
pub extern "C" fn go(data: &[u8]) {
    // fuzzed code goes here
    let _ = der_parser::parse_der(data);
}
