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

use ese_core::{decode_ese_record, EseDatabase, EseValue};

fn open_real() -> Option<EseDatabase> {
    let path = std::env::var("ESE_WEBCACHE").ok()?;
    Some(EseDatabase::open(std::path::Path::new(&path)).expect("open real WebCacheV01.dat"))
}

/// Count the records the cursor yields for a table (defunct entries excluded).
fn record_count(db: &EseDatabase, table: &str) -> usize {
    db.table_records(table)
        .expect("table_records")
        .filter_map(Result::ok)
        .count()
}

/// Bug 3 + tier-1 reconciliation: container/record counts must match
/// `esedbexport` — 35 `Container_#` tables totalling 360 records, and 37 rows in
/// the `Containers` master table.
#[test]
fn record_counts_reconcile_with_esedbexport() {
    let Some(db) = open_real() else {
        eprintln!("skip: ESE_WEBCACHE not set");
        return;
    };
    let entries = db.catalog_entries().expect("catalog");
    let mut container_tables: Vec<String> = entries
        .iter()
        .filter(|e| e.object_type == 1 && e.object_name.starts_with("Container_"))
        .map(|e| e.object_name.clone())
        .collect();
    container_tables.sort();
    container_tables.dedup();
    assert_eq!(
        container_tables.len(),
        35,
        "esedbexport exports 35 Container_# tables"
    );

    let total: usize = container_tables.iter().map(|t| record_count(&db, t)).sum();
    assert_eq!(
        total, 360,
        "total records across Container_# tables must match esedbexport"
    );

    assert_eq!(
        record_count(&db, "Containers"),
        37,
        "the Containers master table has 37 rows"
    );
}

/// Bug 3: a tagged `Url` value from a real `Container_1` record must match the
/// value `esedbexport` exports for that row (EntryId 655).
#[test]
fn container_record_url_matches_oracle() {
    let Some(db) = open_real() else {
        eprintln!("skip: ESE_WEBCACHE not set");
        return;
    };
    let cols = db.table_columns("Container_1").expect("columns");
    let mut url: Option<String> = None;
    for rec in db.table_records("Container_1").expect("records") {
        let (_page, _tag, bytes) = rec.expect("record bytes");
        let vals = decode_ese_record(&bytes, &cols, true).expect("decode");
        let entry_id = vals.iter().find_map(|(n, v)| match (n.as_str(), v) {
            ("EntryId", EseValue::I64(x)) => Some(*x),
            _ => None,
        });
        if entry_id == Some(655) {
            url = vals.iter().find_map(|(n, v)| match (n.as_str(), v) {
                ("Url", EseValue::Text(s)) => Some(s.clone()),
                _ => None,
            });
            break;
        }
    }
    assert_eq!(
        url.as_deref(),
        Some("Visited: 4n6h4x0r@ms-gamingoverlay://kglcheck/"),
        "Container_1 EntryId 655 Url must match esedbexport"
    );
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
