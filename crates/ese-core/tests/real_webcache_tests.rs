#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Tier-1 validation against a REAL Windows `WebCacheV01.dat`.
//!
//! These tests are env-gated on `ESE_WEBCACHE` (path to a real
//! `WebCacheV01.dat`) and skip cleanly when it is absent, exactly like an
//! oracle-binary gate. Ground truth is the independent `esedbexport`
//! (libesedb) tool.
//!
//! The sample used during development is a Windows 11 `WebCacheV01.dat`:
//! ESE format 0x620 rev 20, page size 32768, dirty shutdown, 1120 pages.
//! `esedbexport` reports 35 `Container_#` tables and 37 rows in `Containers`.

use ese_core::EseDatabase;

fn open_real() -> Option<EseDatabase> {
    let path = std::env::var("ESE_WEBCACHE").ok()?;
    Some(EseDatabase::open(std::path::Path::new(&path)).expect("open real WebCacheV01.dat"))
}

/// Bug 2: each `Container_#` table must expose its OWN column set, including the
/// tagged `Url` column (id 256), not a globally name-deduplicated set.
#[test]
fn container_tables_have_own_columns_incl_tagged_url() {
    let Some(db) = open_real() else {
        eprintln!("skip: ESE_WEBCACHE not set");
        return;
    };
    for table in ["Container_1", "Container_2"] {
        let cols = db.table_columns(table).expect("table_columns");
        // esedbinfo reports 25 columns for Container_1/Container_2.
        assert_eq!(cols.len(), 25, "{table} must have its own 25 columns");
        let url = cols
            .iter()
            .find(|c| c.name == "Url")
            .unwrap_or_else(|| panic!("{table} must have its own Url column"));
        assert_eq!(url.column_id, 256, "Url is tagged column id 256");
        assert!(
            cols.iter()
                .any(|c| c.name == "AccessedTime" && c.column_id == 14),
            "{table} must have its fixed AccessedTime column (id 14)"
        );
    }
}

/// Bug 1: walking the catalog B-tree must resolve only in-range child pages.
///
/// Before the large-page tag-mask fix, `walk_leaf_pages(5)` dereferenced an
/// out-of-range child page (physical 1282 on a 1120-page file) and errored
/// with "page beyond file end".
#[test]
fn catalog_btree_walk_resolves_in_range_pages() {
    let Some(db) = open_real() else {
        eprintln!("skip: ESE_WEBCACHE not set");
        return;
    };
    let page_count = db.page_count();
    let leaves = db
        .walk_leaf_pages(5)
        .expect("catalog B-tree must be walkable without out-of-range child pages");
    assert!(
        !leaves.is_empty(),
        "catalog must have at least one leaf page"
    );
    for p in &leaves {
        assert!(
            u64::from(*p) < page_count,
            "leaf page {p} is beyond the {page_count}-page file — child-pointer math is wrong"
        );
    }
}
