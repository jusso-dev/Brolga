//! Every shipping parser, over arbitrary bytes.
//!
//! The target that covers the widest surface: the registry decides which parser claims the input, so
//! this exercises detection *and* parsing for every format at once, including any format added later
//! — because it iterates the registry rather than a list.
//!
//! # What a finding here means
//!
//! A crash is a bug, unconditionally. ADR 0003 §2 says panicking is not a supported way to reject
//! input, and `panic = "abort"` is set for release builds — so a parser panic terminates the process
//! rather than being caught. An unreadable document must be a `ParseError`.
//!
//! # What is deliberately not asserted
//!
//! Nothing about the *records*. A fuzzer's input is almost never a valid document, so an assertion
//! about output would fire on legitimate rejections. The property is that the code returns rather
//! than aborts, and the resource limits keep it from doing so slowly.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = brolga_fuzz::parse_with_every_parser(data);
});
