//! The STIX pattern reader.
//!
//! Its own target rather than only being reached through `ingest_any`, because a pattern is a *nested*
//! grammar: the fuzzer has to get through a valid STIX bundle before reaching it, which it almost
//! never will by chance. Fuzzing the reader directly is the only way this code is actually covered.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    brolga_fuzz::read_stix_pattern(text);
});
