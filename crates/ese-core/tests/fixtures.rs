#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Synthetic ESE database fixture builder for integration tests.
//!
//! Thin wrappers over [`ese_test_fixtures`] that expose the same API the
//! existing btree, catalog and cursor test files already call.
#![allow(dead_code)]

use ese_core::{CatalogEntry, DB_STATE_CLEAN_SHUTDOWN};
use ese_test_fixtures::{make_raw_header_page, EseFileBuilder, PageBuilder, PAGE_SIZE};
use std::io::Write as _;
use tempfile::NamedTempFile;

/// Build a minimal valid ESE file-header page (page 0).
pub fn make_ese_header_page() -> Vec<u8> {
    make_raw_header_page(0, DB_STATE_CLEAN_SHUTDOWN)
}

/// Build a leaf page containing the given raw record byte slices.
///
/// Tag 0 = page header tag (offset=0, size=40).
/// Tags 1..n = record slices, packed starting at offset 40.
///
/// `flags_extra` is accepted for API compatibility but must be 0; all current
/// callers pass 0 and `PageBuilder::leaf()` sets `PAGE_FLAG_LEAF` exactly.
pub fn make_leaf_page_with_records(flags_extra: u32, records: &[Vec<u8>]) -> Vec<u8> {
    debug_assert_eq!(
        flags_extra, 0,
        "non-zero flags_extra not supported via PageBuilder"
    );
    let mut builder = PageBuilder::new(PAGE_SIZE).leaf();
    for rec in records {
        builder = builder.add_record(rec);
    }
    builder.build()
}

/// Build a parent (internal B-tree node) page whose child pointers use the
/// given **ESE page numbers** (0-based data-page numbering, i.e. physical − 1).
///
/// `walk_leaf_pages` adds 1 to each stored value to convert it to a physical
/// page number, so callers must pass `physical_page - 1`.
#[allow(dead_code)]
pub fn make_parent_page_with_children(ese_children: &[u32]) -> Vec<u8> {
    let mut builder = PageBuilder::new(PAGE_SIZE).parent();
    for &ese_page in ese_children {
        builder = builder.add_child_page(ese_page);
    }
    builder.build()
}

/// Build a parent page whose child-reference records each carry a B-tree key
/// prefix *before* the trailing 4-byte child page number.
///
/// Real ESE branch pages store `[key_prefix..][child_page_u32]`; the child page
/// reference is the **last 4 bytes** of the record, not the whole record.
/// `key_prefix` is prepended to every child entry so the traversal must skip it
/// and read only the trailing u32.
#[allow(dead_code)]
pub fn make_parent_page_with_prefixed_children(key_prefix: &[u8], ese_children: &[u32]) -> Vec<u8> {
    let mut builder = PageBuilder::new(PAGE_SIZE).parent();
    for &ese_page in ese_children {
        let mut rec = key_prefix.to_vec();
        rec.extend_from_slice(&ese_page.to_le_bytes());
        builder = builder.add_record(&rec);
    }
    builder.build()
}

/// Write a complete multi-page ESE file to a temp file.
///
/// `pages[0]` is the header page (page 0); subsequent entries are data pages.
pub fn write_ese_file(pages: &[Vec<u8>]) -> NamedTempFile {
    let mut tmp = NamedTempFile::new().expect("tempfile");
    for page in pages {
        tmp.write_all(page).expect("write page");
    }
    tmp
}

/// Build a single-page ESE database with a catalog leaf page at physical page 5.
///
/// Returns a `NamedTempFile` with pages: `[header(0), 1, 2, 3, 4, catalog_leaf(5)]`.
/// Page 5 matches the `CATALOG_ROOT` constant used by `EseDatabase::catalog_entries`.
#[allow(dead_code)]
pub fn make_ese_with_catalog(entries: &[CatalogEntry]) -> NamedTempFile {
    let mut catalog_builder = PageBuilder::new(PAGE_SIZE).leaf();
    for entry in entries {
        catalog_builder = catalog_builder.add_record(&entry.to_bytes());
    }
    let catalog_page = catalog_builder.build();
    let padding = vec![0u8; PAGE_SIZE];
    EseFileBuilder::new()
        .add_page(padding.clone()) // page 1
        .add_page(padding.clone()) // page 2
        .add_page(padding.clone()) // page 3
        .add_page(padding) // page 4
        .add_page(catalog_page) // page 5 = catalog (matches CATALOG_ROOT=5)
        .write()
}
