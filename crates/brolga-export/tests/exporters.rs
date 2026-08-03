//! Shipped exporters: STIX, MISP, JSON, Markdown only.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use brolga_export::ExporterRegistry;

#[test]
fn shipped_exporters_are_the_core_set() {
    let names = ExporterRegistry::shipped().names();
    for required in ["json", "compact", "yaml", "jsonl", "stix", "misp", "markdown", "text", "brief"] {
        assert!(
            names.contains(&required),
            "missing exporter {required}; have {names:?}"
        );
    }
    // Dropped surface must not reappear accidentally.
    for removed in ["csv", "dot", "sarif", "sigma", "hunt"] {
        assert!(
            !names.contains(&removed),
            "removed exporter {removed} still shipped"
        );
    }
}
