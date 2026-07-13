#![no_main]
//! Fuzz the structural integrity analysers. Two surfaces: the byte-slice
//! `EseIntegrity` API run directly over arbitrary data, and the whole-database
//! scanners run over an arbitrary file opened as an ESE database. Must never
//! panic on a corrupt, truncated, or hostile database.
use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    // Byte-slice analysers (no file needed).
    let integ = ese_integrity::EseIntegrity::new(data);
    let _ = integ.analyse();
    let _ = integ.check_layout();
    let _ = integ.check_pages();
    let _ = integ.check_btree();
    let _ = integ.check_catalog();
    let _ = integ.check_header();

    // Whole-database scanners over a temp file.
    let Ok(mut tmp) = tempfile::NamedTempFile::new() else {
        return;
    };
    if tmp.write_all(data).is_err() {
        return;
    }
    let Ok(db) = ese_core::EseDatabase::open(tmp.path()) else {
        return;
    };
    let _ = ese_integrity::full_scan(&db);
    let _ = ese_integrity::verify_page_checksums(&db);
    let _ = ese_integrity::detect_orphaned_catalog(&db);
    let _ = ese_integrity::find_deleted_records(&db);
    let _ = ese_integrity::scan_slack_regions(&db);
    let _ = ese_integrity::check_dirty_state(&db.header);
    let _ = ese_integrity::detect_timestamp_skew(&db.header, &db);
});
