//! Every canonicaliser, over arbitrary text.
//!
//! Canonicalisation is where untrusted values become identifiers, so a crash here is reachable from
//! any feed and a *wrong* answer silently splits or merges intelligence.
//!
//! The target checks two properties rather than only absence of panic:
//!
//! - **Idempotency.** Canonicalising a canonical value returns it unchanged. A canonicaliser that is
//!   not idempotent produces a different identifier on re-ingest, so the same indicator becomes two
//!   observables and correlation quietly stops working.
//! - **No control characters in the output.** A canonical value is rendered in tables, logs, and
//!   packs; one carrying a terminal escape is an injection surface in every one of them.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    brolga_fuzz::canonicalise_every_way(text);
});
