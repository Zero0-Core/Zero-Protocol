#![no_main]
use libfuzzer_sys::fuzz_target;
use zero_core::packet::decode_packet;

fuzz_target!(|data: &[u8]| {
    // The fuzzer will hammer the decode_packet function with arbitrary data
    // to find panics, out-of-bounds reads, or logic errors.
    let _ = decode_packet(data);
});
