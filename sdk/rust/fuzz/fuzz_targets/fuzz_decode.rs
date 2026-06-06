#![no_main]

use libfuzzer_sys::fuzz_target;

// Invariant: decode_envelope must never panic on any UTF-8-valid string input.
// On garbage/malformed input it must return Err(...), not panic.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = aip7h3::decode_envelope(s);
    }
});
