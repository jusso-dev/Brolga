//! Declarative mapping documents.
//!
//! A mapping is *executed* against untrusted input, so a mapping document is itself a trust boundary
//! whenever one arrives from somewhere other than the operator's own hand.
//!
//! Two properties: loading never panics, and a mapping that loads is one that validated — because the
//! whole safety argument for the mapping engine is that validation happens at load time rather than
//! partway through a document.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    brolga_fuzz::load_mapping(data);
});
