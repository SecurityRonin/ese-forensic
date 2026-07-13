#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Integration tests for ese-integrity structural anomaly detection.

mod fixtures;

use ese_core::{DB_STATE_CLEAN_SHUTDOWN, DB_STATE_DIRTY_SHUTDOWN};
use ese_integrity::{
    check_dirty_state, detect_autoinc_gaps, detect_orphaned_catalog, detect_timestamp_skew,
    find_deleted_records, full_scan, scan_slack_regions, verify_page_checksums,
    EseStructuralAnomaly, Severity,
};

// ── check_dirty_state ────────────────────────────────────────────────────────

#[test]
fn dirty_state_returns_none_for_clean_shutdown() {
    let tmp = fixtures::make_ese_with_db_state(DB_STATE_CLEAN_SHUTDOWN);
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomaly = check_dirty_state(&db.header);
    assert!(anomaly.is_none(), "clean shutdown must produce no anomaly");
}

#[test]
fn dirty_state_returns_anomaly_for_dirty_shutdown() {
    let tmp = fixtures::make_ese_with_db_state(DB_STATE_DIRTY_SHUTDOWN);
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomaly = check_dirty_state(&db.header);
    assert!(
        anomaly.is_some(),
        "dirty shutdown must produce DirtyDatabase anomaly"
    );
    if let Some(EseStructuralAnomaly::DirtyDatabase { db_state }) = anomaly {
        assert_eq!(db_state, DB_STATE_DIRTY_SHUTDOWN);
    } else {
        panic!("expected DirtyDatabase variant");
    }
}

// ── detect_timestamp_skew ────────────────────────────────────────────────────

#[test]
fn timestamp_skew_empty_for_page_equal_to_header() {
    // Page db_time == header db_time low32 → no skew
    let tmp = fixtures::make_ese_with_page_db_time(
        /*header_db_time=*/ 1000_u64, /*page_db_time=*/ 1000_u32,
    );
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = detect_timestamp_skew(&db.header, &db);
    assert!(
        anomalies.is_empty(),
        "equal timestamps must produce no anomaly"
    );
}

#[test]
fn timestamp_skew_empty_for_page_older_than_header() {
    let tmp = fixtures::make_ese_with_page_db_time(
        /*header_db_time=*/ 2000_u64, /*page_db_time=*/ 1000_u32,
    );
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = detect_timestamp_skew(&db.header, &db);
    assert!(
        anomalies.is_empty(),
        "page older than header must produce no anomaly"
    );
}

#[test]
fn timestamp_skew_detected_when_page_newer_than_header() {
    // page db_time (5000) > header db_time low32 (1000) → skew
    let tmp = fixtures::make_ese_with_page_db_time(
        /*header_db_time=*/ 1000_u64, /*page_db_time=*/ 5000_u32,
    );
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = detect_timestamp_skew(&db.header, &db);
    assert!(
        !anomalies.is_empty(),
        "page newer than header must produce TimestampSkew"
    );
    let found = anomalies.iter().any(|a| {
        matches!(a, EseStructuralAnomaly::TimestampSkew {
            header_db_time_low,
            page_db_time,
            ..
        } if *header_db_time_low == 1000 && *page_db_time == 5000)
    });
    assert!(found, "TimestampSkew must carry correct field values");
}

// ── severity() ───────────────────────────────────────────────────────────────

#[test]
fn dirty_database_severity_is_info() {
    let a = EseStructuralAnomaly::DirtyDatabase { db_state: 2 };
    assert_eq!(a.severity(), Severity::Info);
}

#[test]
fn timestamp_skew_severity_is_error() {
    let a = EseStructuralAnomaly::TimestampSkew {
        page_number: 1,
        header_db_time_low: 100,
        page_db_time: 500,
    };
    assert_eq!(a.severity(), Severity::High);
}

#[test]
fn slack_region_data_severity_is_warning() {
    let a = EseStructuralAnomaly::SlackRegionData {
        page_number: 2,
        offset_in_page: 80,
        length: 16,
    };
    assert_eq!(a.severity(), Severity::Medium);
}

#[test]
fn page_checksum_mismatch_severity_is_error() {
    let a = EseStructuralAnomaly::PageChecksumMismatch {
        page_number: 3,
        expected: 0xDEAD_BEEF,
        actual: 0x1234_5678,
    };
    assert_eq!(a.severity(), Severity::High);
}

#[test]
fn btree_link_broken_severity_is_error() {
    let a = EseStructuralAnomaly::BTreeLinkBroken {
        page_number: 4,
        broken_sibling: 99,
    };
    assert_eq!(a.severity(), Severity::High);
}

#[test]
fn page_flag_inconsistency_severity_is_warning() {
    let a = EseStructuralAnomaly::PageFlagInconsistency {
        page_number: 5,
        flags: 0x0002,
        context: "leaf flag on internal node",
    };
    assert_eq!(a.severity(), Severity::Medium);
}

#[test]
fn orphaned_srum_table_severity_is_warning() {
    let a = EseStructuralAnomaly::OrphanedSrumTable {
        table_guid: "{deadbeef-dead-beef-dead-beefdeadbeef}".to_owned(),
    };
    assert_eq!(a.severity(), Severity::Medium);
}

#[test]
fn missing_srum_table_severity_is_warning() {
    let a = EseStructuralAnomaly::MissingSrumTable {
        table_guid: "{d10ca2fe-6fcf-4f6d-848e-b2e99266fa89}",
        table_name: "SruDbNetworkUsageTable",
    };
    assert_eq!(a.severity(), Severity::Medium);
}

#[test]
fn truncated_database_severity_is_critical() {
    let a = EseStructuralAnomaly::TruncatedDatabase {
        declared_pages: 100,
        actual_pages: 40,
    };
    assert_eq!(a.severity(), Severity::Critical);
}

// ── at_least() ───────────────────────────────────────────────────────────────

#[test]
fn at_least_exact_severity_returns_true() {
    let a = EseStructuralAnomaly::TimestampSkew {
        page_number: 1,
        header_db_time_low: 100,
        page_db_time: 500,
    };
    // severity() is Error; at_least(Error) must be true
    assert!(a.at_least(Severity::High));
}

#[test]
fn at_least_lower_threshold_returns_true() {
    let a = EseStructuralAnomaly::TimestampSkew {
        page_number: 1,
        header_db_time_low: 100,
        page_db_time: 500,
    };
    // Error >= Warning: true
    assert!(a.at_least(Severity::Medium));
}

#[test]
fn at_least_higher_threshold_returns_false() {
    let a = EseStructuralAnomaly::TimestampSkew {
        page_number: 1,
        header_db_time_low: 100,
        page_db_time: 500,
    };
    // Error >= Critical: false
    assert!(!a.at_least(Severity::Critical));
}

// ── verify_page_checksums (Phase 4, stories 5-8) ────────────────────────────

#[test]
fn verify_page_checksums_empty_for_database_with_unchecked_pages() {
    // Pages built by PageBuilder have 0 stored checksum → "unchecked", must not be reported.
    let tmp = fixtures::make_ese_with_db_state(DB_STATE_CLEAN_SHUTDOWN);
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = verify_page_checksums(&db);
    assert!(
        anomalies.is_empty(),
        "unchecked pages (zero stored checksum) must produce no anomaly"
    );
}

#[test]
fn verify_page_checksums_reports_mismatch_for_tampered_page() {
    let tmp = fixtures::make_ese_with_bad_checksum_on_page1();
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = verify_page_checksums(&db);
    let found = anomalies
        .iter()
        .any(|a| matches!(a, EseStructuralAnomaly::PageChecksumMismatch { .. }));
    assert!(found, "tampered page must produce PageChecksumMismatch");
}

#[test]
fn verify_page_checksums_mismatch_carries_correct_page_number() {
    let tmp = fixtures::make_ese_with_bad_checksum_on_page1();
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = verify_page_checksums(&db);
    let found = anomalies.iter().any(|a| {
        matches!(
            a,
            EseStructuralAnomaly::PageChecksumMismatch { page_number, .. }
                if *page_number == 1
        )
    });
    assert!(found, "mismatch on page 1 must report page_number == 1");
}

#[test]
fn verify_page_checksums_skips_page_with_zero_stored_checksum() {
    // A zero stored checksum means "unchecked" — must be silent even if computed ≠ 0.
    let tmp = fixtures::make_ese_with_page_db_time(0, 0);
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = verify_page_checksums(&db);
    assert!(
        anomalies.is_empty(),
        "page with zero stored checksum must not produce PageChecksumMismatch"
    );
}

// ── scan_slack_regions ───────────────────────────────────────────────────────

#[test]
fn slack_empty_for_page_with_no_slack() {
    // A page whose records exactly fill the available space — no slack bytes
    let tmp = fixtures::make_ese_with_tight_records();
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = scan_slack_regions(&db);
    assert!(
        anomalies.is_empty(),
        "page with no slack must produce no SlackRegionData"
    );
}

#[test]
fn slack_detected_for_page_with_residual_bytes() {
    // A page with records that don't fill the space — non-zero bytes in slack
    let tmp = fixtures::make_ese_with_slack_bytes(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = scan_slack_regions(&db);
    let found = anomalies
        .iter()
        .any(|a| matches!(a, EseStructuralAnomaly::SlackRegionData { length, .. } if *length > 0));
    assert!(
        found,
        "page with non-zero slack must produce SlackRegionData"
    );
}

// ── find_deleted_records (Phase 4, stories 9-12) ─────────────────────────────

#[test]
fn find_deleted_records_empty_for_database_with_no_deleted_records() {
    // A freshly built page has no deleted tags — must return empty.
    let tmp = fixtures::make_ese_with_db_state(DB_STATE_CLEAN_SHUTDOWN);
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = find_deleted_records(&db);
    assert!(
        anomalies.is_empty(),
        "database with no deleted records must produce no anomaly"
    );
}

#[test]
fn find_deleted_records_detects_deleted_tag() {
    // Page with a tag that has the defunct flag set in the offset word (bits 13-15).
    // Per MS-ESEDB spec: TAG_DEFUNCT = 0x2 is stored in bits 13-15 of the offset word
    // (bits 13-15 of the 32-bit tag = mask 0x4000 at bit 14 of the u32).
    let tmp = fixtures::make_ese_with_deleted_record();
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = find_deleted_records(&db);
    let found = anomalies
        .iter()
        .any(|a| matches!(a, EseStructuralAnomaly::DeletedRecordPresent { .. }));
    assert!(
        found,
        "page with deleted tag must produce DeletedRecordPresent"
    );
}

#[test]
fn find_deleted_records_detects_defunct_flag_in_offset_word() {
    // Per MS-ESEDB spec: the defunct (deleted) flag is TAG_DEFUNCT=0x2 in the
    // 3-bit flag field at bits 13-15 of the OFFSET word, i.e. bit 14 of the
    // 32-bit tag word (0x4000). This is the correct location; our old code
    // incorrectly checked bit 29 (0x2000_0000) in the size word.
    use std::io::Write as _;
    let page_size = ese_core::PAGE_SIZE;
    let mut page_data = vec![0u8; page_size];
    page_data[0x22..0x24].copy_from_slice(&2u16.to_le_bytes()); // tag_count=2
    page_data[0x24..0x28].copy_from_slice(&ese_core::PAGE_FLAG_LEAF.to_le_bytes());
    page_data[0x10..0x14].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    page_data[0x14..0x18].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

    // Tag 0: relative offset=0, size=40
    let tag0: u32 = 40u32 << 16;
    page_data[page_size - 4..page_size].copy_from_slice(&tag0.to_le_bytes());

    // Tag 1: defunct flag in OFFSET word (bit 14 = TAG_DEFUNCT=0x2 at bits 13-15).
    // relative offset=0, size=4, defunct bit in offset word.
    // offset_word = 0 | (0x2 << 13) = 0x4000
    // tag_raw = 0x4000 | (4 << 16) = 0x0004_4000
    let tag1: u32 = 0x4000u32 | (4u32 << 16);
    page_data[page_size - 8..page_size - 4].copy_from_slice(&tag1.to_le_bytes());

    let header = ese_test_fixtures::make_raw_header_page(0, ese_core::DB_STATE_CLEAN_SHUTDOWN);
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&header).unwrap();
    tmp.write_all(&page_data).unwrap();

    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = find_deleted_records(&db);
    let found = anomalies
        .iter()
        .any(|a| matches!(a, EseStructuralAnomaly::DeletedRecordPresent { .. }));
    assert!(
        found,
        "defunct flag in offset word (bit 14 = 0x4000) must be detected as DeletedRecordPresent"
    );
}

#[test]
fn find_deleted_records_carries_correct_page_number() {
    let tmp = fixtures::make_ese_with_deleted_record();
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = find_deleted_records(&db);
    let found = anomalies.iter().any(|a| {
        matches!(
            a,
            EseStructuralAnomaly::DeletedRecordPresent { page_number, .. }
                if *page_number == 1
        )
    });
    assert!(
        found,
        "deleted record on page 1 must carry page_number == 1"
    );
}

#[test]
fn deleted_record_present_severity_is_warning() {
    let a = EseStructuralAnomaly::DeletedRecordPresent {
        page_number: 1,
        tag_index: 0,
    };
    assert_eq!(a.severity(), Severity::Medium);
}

// ── detect_autoinc_gaps (Phase 4, stories 13-16) ─────────────────────────────

#[test]
fn detect_autoinc_gaps_empty_for_contiguous_ids() {
    let ids = vec![1i32, 2, 3, 4, 5];
    let anomalies = detect_autoinc_gaps(&ids);
    assert!(
        anomalies.is_empty(),
        "contiguous AutoIncIds must produce no anomaly"
    );
}

#[test]
fn detect_autoinc_gaps_detects_single_gap() {
    // 3 → 5 is a gap (4 is missing)
    let ids = vec![1i32, 2, 3, 5, 6];
    let anomalies = detect_autoinc_gaps(&ids);
    let found = anomalies
        .iter()
        .any(|a| matches!(a, EseStructuralAnomaly::AutoIncIdGap { prev: 3, next: 5 }));
    assert!(
        found,
        "gap between 3 and 5 must produce AutoIncIdGap {{ prev:3, next:5 }}"
    );
}

#[test]
fn detect_autoinc_gaps_empty_for_single_element() {
    let ids = vec![42i32];
    let anomalies = detect_autoinc_gaps(&ids);
    assert!(anomalies.is_empty(), "single element produces no gaps");
}

#[test]
fn autoinc_id_gap_severity_is_warning() {
    let a = EseStructuralAnomaly::AutoIncIdGap { prev: 3, next: 5 };
    assert_eq!(a.severity(), Severity::Medium);
}

// ── detect_orphaned_catalog (Phase 4, stories 17-18) ─────────────────────────

#[test]
fn detect_orphaned_catalog_surfaces_unreadable_catalog_for_database_with_no_catalog() {
    // A minimal fixture has no catalog root page → catalog_entries() fails. The
    // unreadable catalog is the bootstrap structure this detector depends on, so
    // it must surface as a loud CatalogUnreadable anomaly, never silent-empty.
    let tmp = fixtures::make_ese_with_db_state(DB_STATE_CLEAN_SHUTDOWN);
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = detect_orphaned_catalog(&db);
    assert!(
        anomalies
            .iter()
            .any(|a| matches!(a, EseStructuralAnomaly::CatalogUnreadable { .. })),
        "database with inaccessible catalog must produce a CatalogUnreadable anomaly"
    );
}

#[test]
fn detect_orphaned_catalog_reports_orphan_when_table_page_is_out_of_bounds() {
    // Catalog entry references page 100; file only has 6 pages → orphaned.
    let tmp = fixtures::make_ese_with_orphaned_catalog_entry();
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = detect_orphaned_catalog(&db);
    let found = anomalies.iter().any(|a| {
        matches!(
            a,
            EseStructuralAnomaly::OrphanedCatalogEntry {
                declared_page: 100,
                ..
            }
        )
    });
    assert!(
        found,
        "catalog entry with table_page=100 beyond file size must produce OrphanedCatalogEntry"
    );
}

#[test]
fn detect_orphaned_catalog_surfaces_unreadable_catalog_as_anomaly() {
    // The catalog (page 5) is the bootstrap structure this detector depends on.
    // A database with no catalog page makes catalog_entries() fail — an itself
    // suspicious / tamper-consistent condition. The detector MUST surface a loud
    // CatalogUnreadable anomaly, never an empty Vec indistinguishable from a
    // clean catalog (the silent-inversion failure class).
    let tmp = fixtures::make_ese_with_db_state(DB_STATE_CLEAN_SHUTDOWN);
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = detect_orphaned_catalog(&db);
    let found = anomalies
        .iter()
        .any(|a| matches!(a, EseStructuralAnomaly::CatalogUnreadable { .. }));
    assert!(
        found,
        "unreadable catalog must surface as CatalogUnreadable, not silent-empty; got {anomalies:?}"
    );
}

// ── full_scan (Phase 4, stories 19-20) ───────────────────────────────────────

#[test]
fn full_scan_surfaces_unreadable_catalog_via_detect_orphaned_catalog() {
    // The minimal fixture has no catalog root page, so detect_orphaned_catalog —
    // which full_scan aggregates — reports CatalogUnreadable. full_scan must
    // propagate that loud anomaly rather than swallow it into an empty result.
    let tmp = fixtures::make_ese_with_db_state(DB_STATE_CLEAN_SHUTDOWN);
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = full_scan(&db);
    assert!(
        anomalies
            .iter()
            .any(|a| matches!(a, EseStructuralAnomaly::CatalogUnreadable { .. })),
        "full_scan must surface CatalogUnreadable for a database with no catalog page"
    );
}

#[test]
fn full_scan_detects_bad_checksum() {
    // full_scan must include the output of verify_page_checksums.
    let tmp = fixtures::make_ese_with_bad_checksum_on_page1();
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = full_scan(&db);
    let found = anomalies
        .iter()
        .any(|a| matches!(a, EseStructuralAnomaly::PageChecksumMismatch { .. }));
    assert!(
        found,
        "full_scan must surface PageChecksumMismatch from verify_page_checksums"
    );
}

// ── find_deleted_records: real fixture integration ────────────────────────────

const CHAINSAW: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/data/srudb/chainsaw_SRUDB.dat"
);
const RATHBUNVM_WIN10: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/data/srudb/museum_rathbunvm_win10_SRUDB.dat"
);
const RATHBUNVM_WIN11: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/data/srudb/museum_rathbunvm_win11_SRUDB.dat"
);
const APTVM_CLEAN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/data/srudb/museum_aptvm_server2022_clean_SRUDB.dat"
);
const APTVM_1DAY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/data/srudb/museum_aptvm_server2022_1daylater_SRUDB.dat"
);
const BELKASOFT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/data/srudb/museum_belkasoftctf_win10_SRUDB.dat"
);
const PLASO: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/data/srudb/plaso_SRUDB.dat"
);

fn open_real(path: &str) -> Option<ese_core::EseDatabase> {
    let p = std::path::Path::new(path);
    if !p.exists() {
        return None;
    }
    Some(ese_core::EseDatabase::open(p).expect("open real SRUDB"))
}

/// Fresh Server 2022 (no anti-forensics): zero deleted record tags.
#[test]
fn aptvm_clean_has_zero_deleted_records() {
    let Some(db) = open_real(APTVM_CLEAN) else {
        return;
    };
    assert_eq!(
        find_deleted_records(&db).len(),
        0,
        "aptvm_clean: fresh install must have no deleted tags"
    );
}

#[test]
fn aptvm_1day_has_zero_deleted_records() {
    let Some(db) = open_real(APTVM_1DAY) else {
        return;
    };
    assert_eq!(
        find_deleted_records(&db).len(),
        0,
        "aptvm_1day: one-day-old server must have no deleted tags"
    );
}

/// Active SRUM databases accumulate deleted records from Windows housekeeping.
/// Counts verified against independent scan (`probe_real_fixture_counts`, 2026-05-20).
#[test]
fn chainsaw_deleted_record_count_matches_baseline() {
    let Some(db) = open_real(CHAINSAW) else {
        return;
    };
    assert_eq!(
        find_deleted_records(&db).len(),
        54,
        "chainsaw: deleted tag count must match baseline"
    );
}

#[test]
fn rathbunvm_win10_deleted_record_count_matches_baseline() {
    let Some(db) = open_real(RATHBUNVM_WIN10) else {
        return;
    };
    assert_eq!(
        find_deleted_records(&db).len(),
        15,
        "rathbunvm_win10: deleted tag count must match baseline"
    );
}

#[test]
fn rathbunvm_win11_deleted_record_count_matches_baseline() {
    let Some(db) = open_real(RATHBUNVM_WIN11) else {
        return;
    };
    assert_eq!(
        find_deleted_records(&db).len(),
        91,
        "rathbunvm_win11: deleted tag count must match baseline"
    );
}

#[test]
fn belkasoft_deleted_record_count_matches_baseline() {
    let Some(db) = open_real(BELKASOFT) else {
        return;
    };
    assert_eq!(
        find_deleted_records(&db).len(),
        58,
        "belkasoft: deleted tag count must match baseline"
    );
}

#[test]
fn plaso_deleted_record_count_matches_baseline() {
    let Some(db) = open_real(PLASO) else { return };
    assert_eq!(
        find_deleted_records(&db).len(),
        143,
        "plaso: deleted tag count must match baseline"
    );
}

// ── check_dirty_state: all known-good files show clean shutdown ───────────────

#[test]
fn all_real_fixtures_show_clean_shutdown() {
    let paths = [
        CHAINSAW,
        RATHBUNVM_WIN10,
        RATHBUNVM_WIN11,
        APTVM_CLEAN,
        APTVM_1DAY,
        BELKASOFT,
        PLASO,
    ];
    for path in &paths {
        let Some(db) = open_real(path) else { continue };
        assert!(
            check_dirty_state(&db.header).is_none(),
            "{path}: must show clean shutdown, got dirty-state anomaly"
        );
    }
}

// ── verify_page_checksums: regression counts (see docs for investigation note) ─

#[test]
fn chainsaw_page_checksum_count_matches_baseline() {
    let Some(db) = open_real(CHAINSAW) else {
        return;
    };
    assert_eq!(
        verify_page_checksums(&db).len(),
        0,
        "chainsaw: correct ECC-32 algorithm must report zero checksum anomalies on known-good file"
    );
}

#[test]
fn rathbunvm_win10_page_checksum_count_matches_baseline() {
    let Some(db) = open_real(RATHBUNVM_WIN10) else {
        return;
    };
    assert_eq!(verify_page_checksums(&db).len(), 0,
        "rathbunvm_win10: correct ECC-32 algorithm must report zero checksum anomalies on known-good file");
}
