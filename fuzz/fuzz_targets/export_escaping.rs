//! The export escapers, over arbitrary text.
//!
//! Each of these is the single point at which feed text reaches a language another program parses — a
//! spreadsheet, a Markdown renderer, Graphviz, a YAML reader, a STIX pattern parser. An escaper that
//! lets one character through is an injection into that program.
//!
//! The properties are the ones the escapers exist for, checked over generated input rather than only
//! the hostile strings somebody thought of.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    brolga_fuzz::escape_every_way(text);
});
