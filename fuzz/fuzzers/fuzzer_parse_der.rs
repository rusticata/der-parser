#![no_main]
extern crate libfuzzer_sys;
extern crate der_parser;
#[export_name="rust_fuzzer_test_input"]
pub extern fn go(data: &[u8]) {
    // fuzzed code goes here
    let _ = der_parser::parse_der(data);
}
