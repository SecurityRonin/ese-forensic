#![no_main]
//! Fuzz the catalog record parsers over arbitrary bytes: single-entry decode,
//! page-data scan, and the heuristic real-record parser. Must never panic on a
//! malformed catalog page or truncated entry.
use ese_core::CatalogEntry;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Single catalog entry from a length-prefixed / fixed layout.
    let _ = CatalogEntry::from_bytes(data);

    // Scan a page data area for embedded catalog entries.
    let entries = CatalogEntry::scan_catalog_page_data(data);
    for e in entries.iter().take(256) {
        // Round-trip the serializer on anything we managed to parse.
        let _ = e.to_bytes();
    }

    // Heuristic 0xFF00-anchored real-record parser.
    let _ = CatalogEntry::parse_real_catalog_record(data);
});
