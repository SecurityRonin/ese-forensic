#![no_main]
//! Fuzz the top-level database open + page/catalog walk. Write arbitrary bytes
//! to a temp file, open it as an ESE database, and exercise every reader entry
//! point (header parse, page reads, catalog scan, table walk). Must never panic
//! on a corrupt or truncated file.
use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    let Ok(mut tmp) = tempfile::NamedTempFile::new() else {
        return;
    };
    if tmp.write_all(data).is_err() {
        return;
    }
    let path = tmp.path();

    // Header-only open path.
    let _ = ese_core::open(path);

    // Full mmap-backed database.
    let Ok(db) = ese_core::EseDatabase::open(path) else {
        return;
    };
    let pages = db.page_count();
    // Read a bounded number of pages (never trust page_count for allocation).
    for pn in 1..=pages.min(64) {
        let _ = db.read_page(pn as u32);
        let _ = db.raw_page_slice(pn as u32);
    }
    let _ = db.catalog_entries();
    if let Ok(cols) = db.table_columns("MSysObjects") {
        let _ = cols;
    }
    if let Ok(cursor) = db.table_records("MSysObjects") {
        for rec in cursor.take(256) {
            let _ = rec;
        }
    }
});
