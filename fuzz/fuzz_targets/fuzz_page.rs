#![no_main]
//! Fuzz the page-level parsers: header decode, tag table, data area, and
//! per-record slicing over an arbitrary page buffer. Must never panic on a
//! short, lying, or corrupt page.
use ese_core::EsePage;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let page = EsePage {
        page_number: 1,
        data: data.to_vec(),
    };
    let _ = page.parse_header();
    let _ = page.raw_data_area();
    if let Ok(tags) = page.tags() {
        // Never trust the tag count for indexing — bound the iteration.
        for i in 0..tags.len().min(512) {
            let _ = page.record_data(i);
        }
    }
    // Also probe a few indices directly, independent of the tag table.
    for i in 0..8 {
        let _ = page.record_data(i);
    }
});
