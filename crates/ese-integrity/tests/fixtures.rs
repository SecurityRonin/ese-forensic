#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Thin fixture wrappers over [`ese_test_fixtures`] for ese-integrity tests.
#![allow(dead_code)]

use ese_core::CatalogEntry;
use ese_test_fixtures::{EseFileBuilder, PageBuilder, PAGE_SIZE};
use tempfile::NamedTempFile;

pub fn make_ese_with_db_state(db_state: u32) -> NamedTempFile {
    EseFileBuilder::new().with_db_state(db_state).write()
}

pub fn make_ese_with_page_db_time(header_db_time: u64, page_db_time: u32) -> NamedTempFile {
    let data_page = PageBuilder::new(PAGE_SIZE)
        .leaf()
        .with_db_time(page_db_time)
        .add_record(&0xDEAD_BEEFu32.to_le_bytes())
        .build();
    EseFileBuilder::new()
        .with_db_time(header_db_time)
        .with_db_state(ese_core::DB_STATE_CLEAN_SHUTDOWN)
        .add_page(data_page)
        .write()
}

pub fn make_ese_with_tight_records() -> NamedTempFile {
    // Record fills exactly to tag boundary: PAGE_SIZE - 2*4 (tag array) - 40 (header) = 4048 bytes
    let record = vec![0u8; PAGE_SIZE - 8 - 40];
    let data_page = PageBuilder::new(PAGE_SIZE)
        .leaf()
        .add_record(&record)
        .build();
    EseFileBuilder::new()
        .with_db_state(ese_core::DB_STATE_CLEAN_SHUTDOWN)
        .add_page(data_page)
        .write()
}

pub fn make_ese_with_slack_bytes(slack: &[u8]) -> NamedTempFile {
    // Leaf page with only tag0 (page header) — slack region is everything after offset 40
    let data_page = PageBuilder::new(PAGE_SIZE).leaf().with_slack(slack).build();
    EseFileBuilder::new()
        .with_db_state(ese_core::DB_STATE_CLEAN_SHUTDOWN)
        .add_page(data_page)
        .write()
}

/// ESE file with a leaf page that has one "live" record and one deleted record.
///
/// Per MS-ESEDB spec: ESE marks deleted records by setting `TAG_DEFUNCT=0x2` in
/// bits 13-15 of the OFFSET word (bit 14 of the u32 tag = 0x4000).
///
///   `relative_offset` = 0, size = 4, `defunct_flag` in offset word
///   → `tag_raw` = (0 | 0x4000) | (4 << 16) = `0x0004_4000`
pub fn make_ese_with_deleted_record() -> NamedTempFile {
    let mut data_page = vec![0u8; PAGE_SIZE];
    // Vista+ header: page_flags at 0x24
    data_page[0x24..0x28].copy_from_slice(&ese_core::PAGE_FLAG_LEAF.to_le_bytes());
    // Vista+ header: prev/next at 0x10/0x14
    data_page[0x10..0x14].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    data_page[0x14..0x18].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

    // Record payload at absolute byte 40 (HEADER_SIZE + relative_offset=0)
    let payload = [0xAA, 0xBB, 0xCC, 0xDD];
    data_page[40..44].copy_from_slice(&payload);

    // Vista+ header: tag_count at 0x22
    data_page[0x22..0x24].copy_from_slice(&2u16.to_le_bytes());

    // Tag 0 (page header tag): relative offset=0, size=40
    let tag0_raw: u32 = (40u32 & 0x1FFF) << 16;
    let t0_pos = PAGE_SIZE - 4;
    data_page[t0_pos..t0_pos + 4].copy_from_slice(&tag0_raw.to_le_bytes());

    // Tag 1 (deleted record): relative offset=0, size=4, defunct flag in offset word.
    // offset_word = 0x0000 | (TAG_DEFUNCT=0x2 << 13) = 0x4000
    // tag_raw = 0x4000 | (4 << 16) = 0x0004_4000
    let tag1_raw: u32 = 0x4000u32 | (4u32 << 16);
    let t1_pos = PAGE_SIZE - 8;
    data_page[t1_pos..t1_pos + 4].copy_from_slice(&tag1_raw.to_le_bytes());

    EseFileBuilder::new()
        .with_db_state(ese_core::DB_STATE_CLEAN_SHUTDOWN)
        .add_page(data_page)
        .write()
}

/// ESE file with a catalog entry (at page 5) pointing to a non-existent page.
///
/// Layout: page 0 = header, pages 1-4 = blank, page 5 = catalog leaf.
/// Total = 6 pages; the catalog entry references page 100 → orphaned.
/// Page 5 matches the `CATALOG_ROOT` constant in `EseDatabase::catalog_entries`.
pub fn make_ese_with_orphaned_catalog_entry() -> NamedTempFile {
    let entry = CatalogEntry {
        object_type: 1,
        object_id: 2,
        parent_object_id: 1,
        table_page: 100,
        object_name: "OrphanedTable".to_owned(),
    };
    let catalog_leaf = PageBuilder::new(PAGE_SIZE)
        .leaf()
        .add_record(&entry.to_bytes())
        .build();
    let blank = vec![0u8; PAGE_SIZE];
    EseFileBuilder::new()
        .add_page(blank.clone()) // page 1
        .add_page(blank.clone()) // page 2
        .add_page(blank.clone()) // page 3
        .add_page(blank.clone()) // page 4
        .add_page(catalog_leaf) // page 5 = catalog leaf (matches CATALOG_ROOT)
        .write()
}

/// ESE file where page 1 has a non-zero but incorrect XOR checksum.
///
/// An all-zero page body gives `computed = XOR_SEED (0x89ABCDEF)`.
/// We store `0xDEADBEEF` instead, so the check must report a mismatch.
pub fn make_ese_with_bad_checksum_on_page1() -> NamedTempFile {
    let mut bad_page = vec![0u8; PAGE_SIZE];
    bad_page[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    EseFileBuilder::new()
        .with_db_state(ese_core::DB_STATE_CLEAN_SHUTDOWN)
        .add_page(bad_page)
        .write()
}
